<output>
1. A security analyst notices that a user's account has been used to access sensitive data from an unusual geographic location. Which of the following BEST describes this type of detection?
A) Anomaly detection
B) Signature-based detection
C) Heuristic analysis
D) Behavioral analytics
Answer: A) Anomaly detection
Anomaly detection identifies unusual patterns or behaviors that deviate from normal operations. In this case, accessing sensitive data from an unexpected geographic location represents abnormal behavior that would trigger anomaly detection. Signature-based detection looks for known patterns of malicious activity, heuristic analysis uses rules to identify suspicious behavior, and behavioral analytics is broader but doesn't specifically describe this detection method.

Which of the following is the MOST effective method to protect against credential stuffing attacks?
A) Implementing strong password policies
B) Enabling multi-factor authentication (MFA)
C) Using a password manager
D) Disabling account lockout
Answer: B) Enabling multi-factor authentication (MFA)
Credential stuffing attacks reuse leaked credentials across multiple sites. MFA provides additional security layers beyond just passwords, making it much harder for attackers to gain access even if they have valid credentials. Strong password policies alone don't prevent credential reuse, password managers help manage passwords but don't stop credential stuffing, and disabling account lockout actually makes the system more vulnerable.
A company wants to ensure that data is protected both at rest and in transit. Which of the following combinations BEST meets this requirement?
A) AES for data at rest, TLS for data in transit
B) SHA-256 for data at rest, SSL for data in transit
C) RSA for data at rest, IPsec for data in transit
D) DES for data at rest, WPA3 for data in transit
Answer: A) AES for data at rest, TLS for data in transit
AES is a symmetric encryption algorithm suitable for protecting data at rest, while TLS (Transport Layer Security) is the standard protocol for securing data in transit. SHA-256 is a hashing algorithm, not encryption, so it cannot protect data at rest. RSA is asymmetric encryption better suited for key exchange rather than bulk data encryption. DES is outdated and insecure, and WPA3 is wireless encryption, not for general data in transit.
Which of the following is a primary purpose of a digital signature?
A) To encrypt data for confidentiality
B) To ensure data integrity and non-repudiation
C) To compress large files
D) To authenticate users via biometrics
Answer: B) To ensure data integrity and non-repudiation
Digital signatures use cryptographic techniques to verify that data has not been altered and to prove the sender's identity, providing both integrity and non-repudiation. While encryption ensures confidentiality, digital signatures focus on authenticity and integrity verification, not compression, and they're not related to biometric authentication.
A technician is configuring a new server and wants to minimize the attack surface. Which of the following should be done FIRST?
A) Install antivirus software
B) Apply the latest security patches
C) Disable unnecessary services and ports
D) Enable remote administration
Answer: C) Disable unnecessary services and ports
Minimizing the attack surface means reducing the number of entry points an attacker could exploit. Disabling unused services and ports is the fundamental first step before applying patches or installing software. Installing antivirus software is helpful but doesn't reduce attack surface, applying patches is important but comes after initial configuration, and enabling remote administration increases the attack surface.
Which of the following BEST describes the purpose of a security baseline?
A) To provide a standard configuration for systems to reduce vulnerabilities
B) To allow all users full access to all systems
C) To increase system performance
D) To replace the need for firewalls
Answer: A) To provide a standard configuration for systems to reduce vulnerabilities
A security baseline establishes minimum security requirements for systems, ensuring consistent configuration that reduces known vulnerabilities. It doesn't grant unlimited access, doesn't necessarily improve performance, and doesn't eliminate the need for other security controls like firewalls.
A security administrator is implementing a new policy that requires employees to change their passwords every 90 days. This is an example of which type of control?
A) Preventive
B) Detective
C) Corrective
D) Deterrent
Answer: A) Preventive
Preventive controls aim to stop incidents before they occur. Password expiration policies prevent prolonged use of compromised credentials. Detective controls identify issues after they happen, corrective controls address problems once discovered, and deterrent controls discourage unwanted behavior but don't prevent it directly.
Which of the following is the BEST way to protect against a man-in-the-middle (MitM) attack on a public Wi-Fi network?
A) Use a password manager
B) Connect only to trusted networks
C) Use a virtual private network (VPN)
D) Disable automatic Wi-Fi connections
Answer: C) Use a virtual private network (VPN)
A VPN encrypts all traffic between the user and the destination, protecting communications from interception. Password managers help manage credentials but don't prevent MitM attacks, connecting to trusted networks may not be possible in public settings, and disabling automatic connections doesn't address the core encryption issue.
A security analyst is reviewing logs and notices repeated failed login attempts from the same IP address. Which of the following actions should be taken FIRST?
A) Block the IP address at the firewall
B) Notify the user of the failed attempts
C) Investigate the source and determine if it's a brute-force attack
D) Reset the user's password
Answer: C) Investigate the source and determine if it's a brute-force attack
Before taking action, it's essential to understand the nature of the activity. The investigation will determine whether it's a legitimate user having trouble or a potential brute-force attack. Blocking immediately might affect legitimate users, notifying the user too early could alert the attacker, and resetting passwords prematurely assumes compromise.
Which of the following BEST describes the concept of least privilege?
A) Granting users only the access they need to perform their job functions
B) Allowing all users to access all systems
C) Giving administrators full access to all data
D) Restricting access based on location only
Answer: A) Granting users only the access they need to perform their job functions
Least privilege means users should only have the minimum level of access necessary to complete their work tasks. This minimizes potential damage from compromised accounts or insider threats. Granting all users access to everything creates unnecessary exposure, giving administrators full access violates the principle, and location-based restrictions alone don't ensure minimal access.
Which of the following is a characteristic of symmetric encryption?
A) Uses different keys for encryption and decryption
B) Uses the same key for encryption and decryption
C) Is slower than asymmetric encryption
D) Is used primarily for digital signatures
Answer: B) Uses the same key for encryption and decryption
Symmetric encryption uses identical keys for both encryption and decryption processes. This is the opposite of asymmetric encryption which uses different keys. Symmetric encryption is generally faster than asymmetric, and asymmetric encryption is used for digital signatures and key exchange, not symmetric encryption.
A company is concerned about data breaches due to lost or stolen devices. Which of the following is the BEST solution to mitigate this risk?
A) Implementing strong password policies
B) Enabling full-disk encryption
C) Disabling USB ports
D) Installing antivirus software
Answer: B) Enabling full-disk encryption
Full-disk encryption protects data even if devices are lost or stolen by encrypting all data on the storage device. Strong passwords help but don't protect data if the device is compromised, disabling USB ports isn't practical for business operations, and antivirus software protects against malware but not against physical device theft.
Which of the following is a common use of steganography in cybersecurity?
A) Encrypting data with a key
B) Hiding data within another file (e.g., image or audio)
C) Blocking malicious traffic
D) Scanning for vulnerabilities
Answer: B) Hiding data within another file (e.g., image or audio)
Steganography involves concealing information within other files or media without drawing attention. It's often used for covert communication or data exfiltration. Encryption transforms data into unreadable form, blocking traffic is a network control, and scanning for vulnerabilities is a detection method.
A security analyst is reviewing a system and finds that it is running outdated software with known vulnerabilities. What type of risk is this?
A) Threat
B) Vulnerability
C) Exploit
D) Risk
Answer: B) Vulnerability
A vulnerability is a weakness or flaw in a system that could be exploited. Outdated software with known vulnerabilities represents a specific weakness. A threat is a potential cause of harm, an exploit is a method to take advantage of a vulnerability, and risk is the combination of threat and vulnerability.
Which of the following is the MOST effective method to prevent unauthorized access to a wireless network?
A) Changing the default SSID
B) Disabling SSID broadcast
C) Using WPA3 encryption
D) Setting up MAC address filtering
Answer: C) Using WPA3 encryption
WPA3 is the current standard for wireless encryption providing robust security against various attacks. Changing SSID and disabling broadcast provide little security (security through obscurity), and MAC filtering can be easily bypassed. WPA3 offers strong encryption and authentication mechanisms.
Which of the following BEST describes a zero-trust security model?
A) Trust all users inside the network perimeter
B) Verify every user and device before granting access, regardless of location
C) Allow access based on physical location only
D) Rely solely on firewalls for protection
Answer: B) Verify every user and device before granting access, regardless of location
Zero-trust security assumes no implicit trust and requires continuous verification of all users and devices. This approach treats all access requests as potentially hostile. Trusting all users inside the network contradicts zero-trust principles, location-based access is insufficient, and relying solely on firewalls is inadequate.
A user receives an email claiming to be from IT support, asking for their password to "verify account security." This is an example of:
A) Phishing
B) Whaling
C) Tailgating
D) Vishing
Answer: A) Phishing
Phishing involves fraudulent emails or messages designed to trick users into revealing sensitive information like passwords. Whaling targets high-level executives, tailgating is physical security breach, and vishing uses phone calls rather than emails.
Which of the following is a primary benefit of using a SIEM (Security Information and Event Management) system?
A) To block all incoming traffic
B) To centralize and correlate security logs for analysis and alerting
C) To manage user passwords
D) To encrypt all data at rest
Answer: B) To centralize and correlate security logs for analysis and alerting
SIEM systems collect, analyze, and correlate log data from various sources to identify security events and generate alerts. They don't block traffic, manage passwords, or encrypt data - those are other security controls.
Which of the following BEST describes the purpose of a penetration test?
A) To identify vulnerabilities that could be exploited by attackers
B) To install antivirus software on all systems
C) To disable all user accounts
D) To replace the need for firewalls
Answer: A) To identify vulnerabilities that could be exploited by attackers
Penetration testing simulates real-world attacks to find security weaknesses before malicious actors do. It doesn't install software, disable accounts, or replace firewalls.
A company wants to ensure that its data backups are secure and recoverable. Which of the following is the MOST important factor to consider?
A) Backup frequency
B) Storage location and encryption
C) Number of backup copies
D) Backup software version
Answer: B) Storage location and encryption
The security and accessibility of backups depend most critically on where they're stored and how well they're encrypted. While backup frequency and quantity matter, storage location and encryption prevent unauthorized access and data compromise.
Which of the following is a key difference between a virus and a worm?
A) A virus requires user interaction to spread; a worm spreads automatically
B) A worm encrypts files; a virus deletes them
C) A virus is only found in emails; a worm is only on USB drives
D) A virus is detected by signature; a worm is not
Answer: A) A virus requires user interaction to spread; a worm spreads automatically
Viruses require user action to execute (like opening an infected file) while worms can spread autonomously across networks. Both can encrypt or delete files, both can spread through various media, and both are typically detected by signature-based methods.
Which of the following is the BEST way to protect against SQL injection attacks?
A) Using strong passwords
B) Implementing input validation and parameterized queries
C) Disabling all databases
D) Using a firewall only
Answer: B) Implementing input validation and parameterized queries
Input validation filters malicious input and parameterized queries prevent SQL commands from being executed. Strong passwords don't prevent SQL injection, disabling databases isn't practical, and firewalls alone don't address application-layer vulnerabilities.
A security administrator is configuring a system to ensure that only authorized users can access specific files. Which of the following is the BEST control to implement?
A) Role-based access control (RBAC)
B) Data loss prevention (DLP)
C) Full-disk encryption
D) Network segmentation
Answer: A) Role-based access control (RBAC)
RBAC grants access based on job roles, ensuring users only access files relevant to their responsibilities. DLP monitors data movement but doesn't control access, encryption protects data at rest but doesn't manage access, and network segmentation controls network access but not file-level access.
Which of the following BEST describes a security patch?
A) A software update that fixes a known vulnerability
B) A tool used to scan for malware
C) A firewall rule to block traffic
D) A backup of system files
Answer: A) A software update that fixes a known vulnerability
A security patch addresses specific security flaws discovered in software. Scanning tools identify vulnerabilities, firewall rules control network traffic, and backups preserve data but don't fix vulnerabilities.
Which of the following is a primary purpose of a business continuity plan (BCP)?
A) To ensure that critical systems can be restored after a disruption
B) To prevent all cyberattacks
C) To replace the need for backups
D) To manage employee salaries
Answer: A) To ensure that critical systems can be restored after a disruption
A BCP outlines procedures to maintain or quickly resume critical business operations during disruptions. It doesn't prevent all attacks, doesn't replace backups, and isn't related to salary management.
A company is experiencing a ransomware attack. Which of the following should be done FIRST?
A) Pay the ransom to regain access
B) Isolate affected systems to prevent spread
C) Notify the media
D) Reinstall the operating system
Answer: B) Isolate affected systems to prevent spread
Immediate isolation prevents the ransomware from spreading to other systems. Paying ransoms is risky and ineffective, notifying media isn't urgent, and reinstallation should come after containment.
Which of the following is the BEST method to verify the integrity of a downloaded file?
A) Check the file size
B) Compare the file's hash value with the published hash
C) Open the file to see if it works
D) Scan it with antivirus software
Answer: B) Compare the file's hash value with the published hash
Hash values provide cryptographic verification of file integrity. File size checks are unreliable, opening files can be dangerous, and antivirus scanning detects malware but doesn't verify file integrity.
Which of the following BEST describes the purpose of a change control board (CCB)?
A) To approve or reject changes to systems to maintain stability and security
B) To manage user passwords
C) To install software updates
D) To block all network traffic
Answer: A) To approve or reject changes to systems to maintain stability and security
The CCB reviews and approves system changes to ensure they don't introduce vulnerabilities or destabilize operations. It doesn't manage passwords, install updates, or block traffic.
Which of the following is a common example of a physical security control?
A) Firewall
B) Biometric scanner
C) Antivirus software
D) Encryption
Answer: B) Biometric scanner
Physical security controls protect physical assets and facilities. Biometric scanners are physical access controls. Firewalls are network controls, antivirus is software-based, and encryption is logical security.
A security engineer is implementing a new authentication system that requires users to provide a password and a one-time code from a mobile app. This is an example of:
A) Single-factor authentication
B) Two-factor authentication (2FA)
C) Multi-factor authentication (MFA)
D) Biometric authentication
Answer: C) Multi-factor authentication (MFA)
MFA uses two or more authentication factors from different categories. Password + one-time code represents two factors (something you know + something you have). 2FA is a subset of MFA, and biometric authentication is a different factor category.
Which of the following is the MOST effective way to prevent unauthorized access to a network via wireless access points?
A) Use WEP encryption
B) Disable SSID broadcasting
C) Implement MAC filtering
D) Use WPA3 with strong passwords
Answer: D) Use WPA3 with strong passwords
WPA3 is the current standard for wireless security with robust encryption. WEP is outdated and insecure, disabling SSID broadcast provides minimal security, and MAC filtering can be easily bypassed.
Which of the following BEST describes a threat actor who targets high-profile individuals such as CEOs?
A) Script kiddie
B) Nation-state
C) Whistleblower
D) Executive-level target (whaling)
Answer: D) Executive-level target (whaling)
Whaling specifically refers to targeting high-value individuals like executives. Script kiddies are unskilled attackers, nation-states are state-sponsored actors, and whistleblowers are individuals exposing wrongdoing.
A company wants to ensure that its employees are aware of security risks and best practices. Which of the following is the BEST approach?
A) Conduct regular security awareness training
B) Install antivirus software
C) Disable all internet access
D) Replace all computers
Answer: A) Conduct regular security awareness training
Training educates users about security risks and proper practices. Antivirus software protects against malware, disabling internet access isn't practical, and replacing computers is expensive and unnecessary.
Which of the following is a key component of a disaster recovery plan (DRP)?
A) Backup frequency and recovery time objectives (RTO)
B) Employee vacation schedules
C) Office furniture layout
D) Marketing campaign plans
Answer: A) Backup frequency and recovery time objectives (RTO)
DRP focuses on restoring systems and data after disasters. RTO defines acceptable downtime, and backup frequency determines recovery capabilities. Other options aren't related to disaster recovery planning.
Which of the following is a primary purpose of a vulnerability scanner?
A) To block malicious traffic in real time
B) To identify and report potential security weaknesses
C) To encrypt all data on the network
D) To manage user accounts
Answer: B) To identify and report potential security weaknesses
Vulnerability scanners scan systems to find known vulnerabilities. They don't block traffic, encrypt data, or manage accounts.
Which of the following is the BEST way to prevent unauthorized access to a network via wireless access points?
A) Use WEP encryption
B) Disable SSID broadcasting
C) Implement MAC filtering
D) Use WPA3 with strong passwords
Answer: D) Use WPA3 with strong passwords
WPA3 is the current standard for wireless security with robust protection. WEP is insecure, disabling SSID broadcast provides minimal protection, and MAC filtering can be bypassed.
Which of the following BEST describes the purpose of a security policy?
A) To define acceptable use and security requirements
B) To replace the need for training
C) To manage hardware inventory
D) To increase system performance
Answer: A) To define acceptable use and security requirements
Security policies establish organizational security standards and expectations. They don't replace training, manage inventory, or improve performance.
A security analyst discovers that a system has been compromised and is communicating with a known malicious IP address. Which of the following should be done FIRST?
A) Reinstall the operating system
B) Disconnect the system from the network
C) Notify the user
D) Change the password
Answer: B) Disconnect the system from the network
Immediate network disconnection prevents further communication with attackers and limits damage. Reinstalling OS is premature, notifying the user may alert the attacker, and changing passwords isn't the immediate priority.
Which of the following is a primary benefit of using a secure boot process?
A) To prevent unauthorized firmware from loading
B) To increase system speed
C) To allow all software to run
D) To disable encryption
Answer: A) To prevent unauthorized firmware from loading
Secure boot verifies the integrity of boot components to ensure only trusted software runs. It doesn't increase speed, allows all software, or disables encryption.
Which of the following is the BEST method to protect data on a mobile device if it is lost or stolen?
A) Use a strong password
B) Enable remote wipe capability
C) Disable Bluetooth
D) Store the device in a safe
Answer: B) Enable remote wipe capability
Remote wipe allows deletion of data if device is lost or stolen. Strong passwords help but don't protect data, disabling Bluetooth is impractical, and storing in a safe doesn't help if device is stolen.
A company is implementing a new system and wants to ensure that it is secure from the start. Which of the following is the BEST approach?
A) Add security controls after deployment
B) Use a secure development lifecycle (SDLC)
C) Rely on third-party testing only
D) Disable all security features to improve performance
Answer: B) Use a secure development lifecycle (SDLC)
SDLC integrates security throughout the development process. Adding controls after deployment is less effective, relying only on third-party testing leaves gaps, and disabling security features creates vulnerabilities.
Which of the following is a primary purpose of a risk assessment?
A) To identify threats, vulnerabilities, and potential impacts
B) To replace the need for backups
C) To install antivirus software
D) To manage employee benefits
Answer: A) To identify threats, vulnerabilities, and potential impacts
Risk assessments systematically identify potential risks to inform security decisions. They don't replace backups, install software, or manage benefits.
Which of the following BEST describes a false negative in security monitoring?
A) A legitimate activity being flagged as malicious
B) A malicious activity going undetected
C) A system crash during a scan
D) A user forgetting their password
Answer: B) A malicious activity going undetected
False negatives occur when threats are missed by detection systems. False positives flag legitimate activities as threats. System crashes and password issues are unrelated to detection accuracy.
Which of the following is the MOST secure method for transmitting sensitive data over the internet?
A) HTTP
B) FTP
C) TLS
D) SMTP
Answer: C) TLS
TLS provides encryption and authentication for secure communication. HTTP and FTP transmit data in plaintext, SMTP is for email transmission, not secure data transfer.
A security administrator wants to ensure that only specific devices can connect to the network. Which of the following is the BEST control?
A) MAC filtering
B) WPA2 encryption
C) Strong passwords
D) Firewall rules
Answer: A) MAC filtering
MAC filtering restricts network access to specific hardware addresses. WPA2 provides wireless encryption, strong passwords are for authentication, and firewall rules control network traffic but don't restrict specific devices.
Which of the following is a key benefit of using a cloud access security broker (CASB)?
A) To manage physical access to data centers
B) To enforce security policies across cloud services
C) To replace the need for firewalls
D) To increase internet speed
Answer: B) To enforce security policies across cloud services
CASBs provide visibility and control over cloud service usage. They don't manage physical access, don't replace firewalls, and don't improve internet speed.
Which of the following BEST describes the purpose of a digital certificate?
A) To encrypt data at rest
B) To verify the identity of a website or user
C) To manage user accounts
D) To block spam emails
Answer: B) To verify the identity of a website or user
Digital certificates use public key infrastructure to authenticate identities. They don't encrypt data at rest, manage accounts, or block spam.
A company is concerned about employees downloading unauthorized software. Which of the following is the BEST solution?
A) Use a firewall
B) Implement application whitelisting
C) Disable all internet access
D) Install antivirus software only
Answer: B) Implement application whitelisting
Application whitelisting allows only approved software to run. Firewalls control network traffic, disabling internet access is impractical, and antivirus software detects but doesn't prevent unauthorized downloads.
Which of the following is a primary purpose of a security audit?
A) To evaluate compliance with security policies and identify gaps
B) To replace the need for training
C) To manage employee payroll
D) To install software updates
Answer: A) To evaluate compliance with security policies and identify gaps
Security audits assess adherence to policies and identify deficiencies. They don't replace training, manage payroll, or install updates.
Which of the following is the BEST way to protect against social engineering attacks?
A) Use strong passwords
B) Conduct regular security awareness training
C) Disable all email
D) Use only wired connections
Answer: B) Conduct regular security awareness training
Training helps users recognize and avoid social engineering tactics. Strong passwords don't prevent manipulation, disabling email is impractical, and wired connections don't address social engineering.
A security analyst is reviewing a system and finds that it is using a deprecated encryption algorithm. Which of the following should be done?
A) Replace it with a stronger, modern algorithm
B) Continue using it until the system fails
C) Disable all encryption
D) Use it only for backups
Answer: A) Replace it with a stronger, modern algorithm
Deprecated algorithms are insecure and should be replaced immediately. Continuing to use them exposes systems to attacks, disabling encryption removes protection, and using for backups is still insecure.
Which of the following is a primary purpose of a firewall rule that allows only specific traffic?
A) To follow the principle of least privilege
B) To block all traffic
C) To increase network speed
D) To disable logging
Answer: A) To follow the principle of least privilege
Allowing only necessary traffic implements least privilege by restricting access to only required services. Blocking all traffic would prevent legitimate access, increasing speed isn't the purpose, and disabling logging reduces security monitoring.
Which of the following BEST describes the purpose of a honeypot?
A) To attract and detect attackers by mimicking a vulnerable system
B) To encrypt all user data
C) To block all incoming traffic
D) To manage user passwords
Answer: A) To attract and detect attackers by mimicking a vulnerable system
Honeypots are decoy systems designed to detect and study attacker behavior. They don't encrypt data, block traffic, or manage passwords.
A company wants to ensure that its data is protected even if a backup is compromised. Which of the following is the BEST solution?
A) Use strong passwords
B) Encrypt backups
C) Store backups in the same location
D) Disable all backups
Answer: B) Encrypt backups
Encryption protects backup data even if storage locations are compromised. Strong passwords don't protect backups, storing in same location doesn't enhance security, and disabling backups creates data loss risk.
Which of the following is a key benefit of using a secure configuration baseline?
A) It reduces the number of security policies
B) It ensures systems are configured securely from the start
C) It increases system performance
D) It eliminates the need for audits
Answer: B) It ensures systems are configured securely from the start
Secure baselines provide standardized, secure configurations. They don't reduce policies, don't necessarily improve performance, and don't eliminate audits.
Which of the following BEST describes a security incident?
A) Any event that threatens the confidentiality, integrity, or availability of information
B) A system reboot
C) A user changing their password
D) A software update
Answer: A) Any event that threatens the confidentiality, integrity, or availability of information
Security incidents include breaches, attacks, and other events that compromise information security. Routine operations like reboots and password changes aren't incidents.
Which of the following is the MOST effective way to prevent data leakage through email?
A) Use strong passwords
B) Implement data loss prevention (DLP)
C) Disable all email accounts
D) Use only internal messaging
Answer: B) Implement data loss prevention (DLP)
DLP systems monitor and control data movement to prevent unauthorized disclosure. Strong passwords don't prevent email leakage, disabling email is impractical, and internal messaging alone isn't sufficient.
A security engineer is configuring a system to ensure that only authorized users can access sensitive data. Which of the following is the BEST control?
A) Role-based access control (RBAC)
B) Full-disk encryption
C) Network segmentation
D) Antivirus software
Answer: A) Role-based access control (RBAC)
RBAC assigns access based on user roles, ensuring appropriate permissions. Full-disk encryption protects data at rest, network segmentation controls network access, and antivirus detects malware but doesn't control access.
Which of the following is a primary purpose of a business impact analysis (BIA)?
A) To identify critical systems and their recovery priorities
B) To manage employee schedules
C) To install new software
D) To replace the need for backups
Answer: A) To identify critical systems and their recovery priorities
BIA determines which systems are most critical and how quickly they must be restored. It doesn't manage schedules, install software, or replace backups.
Which of the following BEST describes the purpose of a recovery point objective (RPO)?
A) The maximum acceptable amount of data loss measured in time
B) The maximum acceptable downtime
C) The time to restore a system after failure
D) The number of backup copies
Answer: A) The maximum acceptable amount of data loss measured in time
RPO defines how much data loss is acceptable based on time intervals. RTO is maximum downtime, restoration time is different from data loss, and backup count is a separate metric.
A company is implementing a new cloud-based application. Which of the following is the BEST way to ensure security?
A) Rely on the cloud provider's default settings
B) Perform a security assessment and apply hardening
C) Disable all security features to improve performance
D) Use only public access
Answer: B) Perform a security assessment and apply hardening
Security assessments identify vulnerabilities and hardening applies protective measures. Default settings may not meet security requirements, disabling features creates vulnerabilities, and public access increases risk.
Which of the following is a primary purpose of a security policy?
A) To define acceptable behavior and security requirements
B) To manage hardware inventory
C) To increase system speed
D) To replace the need for training
Answer: A) To define acceptable behavior and security requirements
Security policies establish organizational security standards and expectations. They don't manage inventory, increase speed, or replace training.
Which of the following BEST describes the purpose of a security awareness program?
A) To educate users about security risks and best practices
B) To replace the need for firewalls
C) To install software updates
D) To manage employee benefits
Answer: A) To educate users about security risks and best practices
Awareness programs train users to recognize threats and follow security procedures. They don't replace firewalls, install updates, or manage benefits.
A security analyst notices that a user account has been used to access a system at an unusual time. Which of the following is the BEST action?
A) Immediately disable the account
B) Investigate the activity to determine if it's legitimate
C) Change the user's password
D) Notify the user
Answer: B) Investigate the activity to determine if it's legitimate
Investigation determines whether it's authorized access or a security incident. Immediate disabling might affect legitimate users, changing passwords assumes compromise, and notifying the user may alert attackers.
Which of the following is the BEST method to protect against credential theft?
A) Use long, complex passwords
B) Enable multi-factor authentication (MFA)
C) Share passwords with coworkers
D) Use the same password across sites
Answer: B) Enable multi-factor authentication (MFA)
MFA adds additional security layers beyond passwords. Long passwords help but don't prevent credential theft, sharing passwords is insecure, and using same passwords increases risk.
Which of the following is a key benefit of using a secure development lifecycle (SDLC)?
A) It reduces the number of security controls
B) It integrates security into every phase of development
C) It increases system performance
D) It eliminates the need for testing
Answer: B) It integrates security into every phase of development
SDLC incorporates security considerations throughout the development process. It doesn't reduce controls, doesn't necessarily improve performance, and doesn't eliminate testing.
Which of the following BEST describes the purpose of a vulnerability assessment?
A) To exploit vulnerabilities in a system
B) To identify and report potential security weaknesses
C) To block all network traffic
D) To encrypt all data
Answer: B) To identify and report potential security weaknesses
Vulnerability assessments scan systems to find weaknesses. They don't exploit vulnerabilities, block traffic, or encrypt data.
A company wants to ensure that its employees are not sharing sensitive data on social media. Which of the following is the BEST solution?
A) Use strong passwords
B) Implement a social media policy and training
C) Disable all internet access
D) Install antivirus software
Answer: B) Implement a social media policy and training
Policies and training educate employees about appropriate social media use. Strong passwords don't address social media, disabling internet is impractical, and antivirus doesn't control social media sharing.
Which of the following is a primary purpose of a change management process?
A) To ensure changes are reviewed and approved to prevent unintended risks
B) To allow immediate deployment of all updates
C) To disable security controls
D) To reduce documentation
Answer: A) To ensure changes are reviewed and approved to prevent unintended risks
Change management reviews modifications to prevent system instability or security issues. It doesn't allow immediate deployment, disables controls, or reduces documentation.
Which of the following BEST describes the purpose of a risk register?
A) To track and manage identified risks and mitigation strategies
B) To store employee passwords
C) To manage backup schedules
D) To replace the need for audits
Answer: A) To track and manage identified risks and mitigation strategies
A risk register documents risks, their likelihood, impact, and planned responses. It doesn't store passwords, manage backups, or replace audits.
Which of the following is the PRIMARY purpose of a security incident response plan?
A) To prevent all security incidents from occurring
B) To provide a structured approach for handling security incidents
C) To eliminate the need for security training
D) To reduce the number of security policies
Answer: B) To provide a structured approach for handling security incidents
A security incident response plan establishes clear procedures for detecting, analyzing, containing, eradicating, and recovering from security incidents. It doesn't prevent all incidents (which is impossible), doesn't eliminate training needs, and doesn't reduce policy requirements.
A company is implementing a new security policy that requires all users to undergo annual security training. This is an example of which type of control?
A) Preventive
B) Detective
C) Corrective
D) Deterrent
Answer: A) Preventive
Preventive controls aim to stop incidents before they occur. Annual security training helps prevent security incidents by educating users about threats and best practices. Detective controls identify issues after they happen, corrective controls address problems after discovery, and deterrent controls discourage unwanted behavior but don't prevent it directly.
Which of the following BEST describes the purpose of a security baseline configuration?
A) To establish minimum security requirements for systems
B) To maximize system performance
C) To disable all security features
D) To allow unlimited user access
Answer: A) To establish minimum security requirements for systems
Security baselines define the minimum acceptable security configuration for systems to reduce vulnerabilities. They don't maximize performance, disable security, or allow unlimited access.
A security analyst is investigating a potential data breach and discovers that an employee's account was used to access sensitive files. Which of the following should be investigated FIRST?
A) The employee's recent password changes
B) The employee's network access logs
C) The employee's physical access records
D) The employee's email communications
Answer: B) The employee's network access logs
Network access logs show when and how the account was accessed, helping determine if it was legitimate or compromised. Password changes don't reveal access patterns, physical access isn't relevant to digital breaches, and email communications are secondary evidence.
Which of the following is the MOST effective method to protect against cross-site scripting (XSS) attacks?
A) Using strong passwords
B) Implementing input validation and sanitization
C) Installing antivirus software
D) Disabling JavaScript in browsers
Answer: B) Implementing input validation and sanitization
Input validation and sanitization prevent malicious script code from being executed by removing or escaping dangerous characters. Strong passwords don't prevent XSS, antivirus software detects malware but not XSS, and disabling JavaScript breaks many legitimate websites.
A company wants to ensure that its data is protected both at rest and in transit. Which of the following encryption methods should be used for each?
A) AES for data at rest, TLS for data in transit
B) RSA for data at rest, SSL for data in transit
C) SHA-256 for data at rest, IPsec for data in transit
D) DES for data at rest, WPA3 for data in transit
Answer: A) AES for data at rest, TLS for data in transit
AES is a symmetric encryption algorithm ideal for protecting data at rest. TLS is the standard protocol for securing data in transit. RSA is asymmetric encryption better for key exchange, SHA-256 is hashing not encryption, DES is outdated and insecure, WPA3 is wireless encryption.
Which of the following is a PRIMARY benefit of using a SIEM (Security Information and Event Management) system?
A) To block all malicious traffic in real time
B) To centralize and correlate security logs for analysis and alerting
C) To manage user passwords
D) To encrypt all data at rest
Answer: B) To centralize and correlate security logs for analysis and alerting
SIEM systems collect, analyze, and correlate log data from multiple sources to identify security events and generate alerts. They don't block traffic, manage passwords, or encrypt data.
Which of the following BEST describes a security incident?
A) Any event that could potentially threaten information security
B) A system reboot
C) A user changing their password
D) A software update
Answer: A) Any event that could potentially threaten information security
A security incident includes any event that compromises confidentiality, integrity, or availability of information. Routine operations like reboots and password changes aren't incidents, and software updates are normal maintenance.
A company is implementing a new authentication system that requires users to provide a password and a fingerprint scan. This is an example of:
A) Single-factor authentication
B) Two-factor authentication (2FA)
C) Multi-factor authentication (MFA)
D) Biometric authentication
Answer: C) Multi-factor authentication (MFA)
MFA uses two or more authentication factors from different categories. Password + fingerprint represents two factors (something you know + something you are). 2FA is a subset of MFA, and biometric authentication is just one factor category.
Which of the following is the MOST effective way to prevent data leakage through email?
A) Use strong passwords
B) Implement data loss prevention (DLP)
C) Disable all email accounts
D) Use only internal messaging
Answer: B) Implement data loss prevention (DLP)
DLP systems monitor and control email content to prevent unauthorized data transfer. Strong passwords don't prevent email leakage, disabling email is impractical, and internal messaging alone isn't sufficient protection.
Which of the following BEST describes the purpose of a risk assessment?
A) To identify threats, vulnerabilities, and potential impacts
B) To install antivirus software
C) To manage employee benefits
D) To replace the need for backups
Answer: A) To identify threats, vulnerabilities, and potential impacts
Risk assessments systematically identify potential risks to inform security decisions. They don't install software, manage benefits, or replace backups.
A security administrator wants to ensure that only specific devices can connect to the wireless network. Which of the following is the BEST control?
A) MAC filtering
B) WPA3 encryption
C) Strong passwords
D) Firewall rules
Answer: A) MAC filtering
MAC filtering restricts network access to specific hardware addresses. WPA3 provides wireless encryption, strong passwords are for authentication, and firewall rules control network traffic but don't restrict specific devices.
Which of the following is a PRIMARY purpose of a security policy?
A) To define acceptable behavior and security requirements
B) To manage hardware inventory
C) To increase system performance
D) To replace the need for training
Answer: A) To define acceptable behavior and security requirements
Security policies establish organizational security standards and expectations. They don't manage inventory, increase performance, or replace training.
Which of the following BEST describes the purpose of a security awareness program?
A) To educate users about security risks and best practices
B) To install antivirus software
C) To manage employee payroll
D) To replace the need for firewalls
Answer: A) To educate users about security risks and best practices
Security awareness programs train users to recognize threats and follow security procedures. They don't install software, manage payroll, or replace firewalls.
A security analyst discovers that a system has been compromised and is communicating with a known malicious IP address. Which of the following should be done FIRST?
A) Reinstall the operating system
B) Disconnect the system from the network
C) Notify the user
D) Change the password
Answer: B) Disconnect the system from the network
Immediate network disconnection prevents further communication with attackers and limits damage. Reinstalling OS is premature, notifying the user may alert the attacker, and changing passwords isn't the immediate priority.
Which of the following is the BEST method to verify the integrity of a downloaded file?
A) Check the file size
B) Compare the file's hash value with the published hash
C) Open the file to see if it works
D) Scan it with antivirus software
Answer: B) Compare the file's hash value with the published hash
Hash values provide cryptographic verification of file integrity. File size checks are unreliable, opening files can be dangerous, and antivirus scanning detects malware but doesn't verify file integrity.
Which of the following is a PRIMARY benefit of using a secure boot process?
A) To prevent unauthorized firmware from loading
B) To increase system speed
C) To allow all software to run
D) To disable encryption
Answer: A) To prevent unauthorized firmware from loading
Secure boot verifies the integrity of boot components to ensure only trusted software runs. It doesn't increase speed, allows all software, or disables encryption.
Which of the following BEST describes a false negative in security monitoring?
A) A legitimate activity being flagged as malicious
B) A malicious activity going undetected
C) A system crash during a scan
D) A user forgetting their password
Answer: B) A malicious activity going undetected
False negatives occur when threats are missed by detection systems. False positives flag legitimate activities as threats. System crashes and password issues are unrelated to detection accuracy.
A company is concerned about employees downloading unauthorized software. Which of the following is the BEST solution?
A) Use a firewall
B) Implement application whitelisting
C) Disable all internet access
D) Install antivirus software only
Answer: B) Implement application whitelisting
Application whitelisting allows only approved software to run. Firewalls control network traffic, disabling internet access is impractical, and antivirus software detects but doesn't prevent unauthorized downloads.
Which of the following is the MOST secure method for transmitting sensitive data over the internet?
A) HTTP
B) FTP
C) TLS
D) SMTP
Answer: C) TLS
TLS provides encryption and authentication for secure communication. HTTP and FTP transmit data in plaintext, SMTP is for email transmission, not secure data transfer.
Which of the following is a PRIMARY purpose of a vulnerability scanner?
A) To block malicious traffic in real time
B) To identify and report potential security weaknesses
C) To encrypt all data on the network
D) To manage user accounts
Answer: B) To identify and report potential security weaknesses
Vulnerability scanners scan systems to find known vulnerabilities. They don't block traffic, encrypt data, or manage accounts.
Which of the following BEST describes a threat actor who targets high-profile individuals such as CEOs?
A) Script kiddie
B) Nation-state
C) Whistleblower
D) Executive-level target (whaling)
Answer: D) Executive-level target (whaling)
Whaling specifically refers to targeting high-value individuals like executives. Script kiddies are unskilled attackers, nation-states are state-sponsored actors, and whistleblowers are individuals exposing wrongdoing.
A company wants to ensure that its data backups are secure and recoverable. Which of the following is the MOST important factor to consider?
A) Backup frequency
B) Storage location and encryption
C) Number of backup copies
D) Backup software version
Answer: B) Storage location and encryption
The security and accessibility of backups depend most critically on where they're stored and how well they're encrypted. While backup frequency and quantity matter, storage location and encryption prevent unauthorized access and data compromise.
Which of the following is the BEST way to protect against credential stuffing attacks?
A) Implementing strong password policies
B) Enabling multi-factor authentication (MFA)
C) Using a password manager
D) Disabling account lockout
Answer: B) Enabling multi-factor authentication (MFA)
Credential stuffing attacks reuse leaked credentials across multiple sites. MFA provides additional security layers beyond just passwords, making it much harder for attackers to gain access even if they have valid credentials. Strong password policies alone don't prevent credential reuse, password managers help manage passwords but don't stop credential stuffing, and disabling account lockout actually makes the system more vulnerable.
Which of the following is a PRIMARY purpose of a business continuity plan (BCP)?
A) To ensure that critical systems can be restored after a disruption
B) To prevent all cyberattacks
C) To replace the need for backups
D) To manage employee salaries
Answer: A) To ensure that critical systems can be restored after a disruption
A BCP outlines procedures to maintain or quickly resume critical business operations during disruptions. It doesn't prevent all attacks, doesn't replace backups, and isn't related to salary management.
Which of the following BEST describes the purpose of a digital certificate?
A) To encrypt data at rest
B) To verify the identity of a website or user
C) To manage user accounts
D) To block spam emails
Answer: B) To verify the identity of a website or user
Digital certificates use public key infrastructure to authenticate identities. They don't encrypt data at rest, manage accounts, or block spam.
A company is implementing a new system and wants to ensure that it is secure from the start. Which of the following is the BEST approach?
A) Add security controls after deployment
B) Use a secure development lifecycle (SDLC)
C) Rely on third-party testing only
D) Disable all security features to improve performance
Answer: B) Use a secure development lifecycle (SDLC)
SDLC integrates security throughout the development process. Adding controls after deployment is less effective, relying only on third-party testing leaves gaps, and disabling security features creates vulnerabilities.
Which of the following is a PRIMARY benefit of using a cloud access security broker (CASB)?
A) To manage physical access to data centers
B) To enforce security policies across cloud services
C) To replace the need for firewalls
D) To increase internet speed
Answer: B) To enforce security policies across cloud services
CASBs provide visibility and control over cloud service usage. They don't manage physical access, don't replace firewalls, and don't improve internet speed.
Which of the following BEST describes a security baseline?
A) To provide a standard configuration for systems to reduce vulnerabilities
B) To allow all users full access to all systems
C) To increase system performance
D) To replace the need for firewalls
Answer: A) To provide a standard configuration for systems to reduce vulnerabilities
A security baseline establishes minimum security requirements for systems, ensuring consistent configuration that reduces known vulnerabilities. It doesn't grant unlimited access, doesn't necessarily improve performance, and doesn't eliminate the need for other security controls like firewalls.
Which of the following is the BEST way to protect against social engineering attacks?
A) Use strong passwords
B) Conduct regular security awareness training
C) Disable all email
D) Use only wired connections
Answer: B) Conduct regular security awareness training
Training helps users recognize and avoid social engineering tactics. Strong passwords don't prevent manipulation, disabling email is impractical, and wired connections don't address social engineering.
Which of the following BEST describes the purpose of a security audit?
A) To evaluate compliance with security policies and identify gaps
B) To replace the need for training
C) To manage employee payroll
D) To install software updates
Answer: A) To evaluate compliance with security policies and identify gaps
Security audits assess adherence to policies and identify deficiencies. They don't replace training, manage payroll, or install updates.
Which of the following is a PRIMARY purpose of a disaster recovery plan (DRP)?
A) To ensure that critical systems can be restored after a disruption
B) To prevent all cyberattacks
C) To replace the need for backups
D) To manage employee schedules
Answer: A) To ensure that critical systems can be restored after a disruption
A DRP outlines procedures to restore systems and data after disasters. It doesn't prevent all attacks, doesn't replace backups, and isn't related to schedule management.
Which of the following BEST describes the purpose of a security incident response plan?
A) To provide a structured approach for handling security incidents
B) To prevent all security incidents from occurring
C) To eliminate the need for security training
D) To reduce the number of security policies
Answer: A) To provide a structured approach for handling security incidents
A security incident response plan establishes clear procedures for detecting, analyzing, containing, eradicating, and recovering from security incidents. It doesn't prevent all incidents (which is impossible), doesn't eliminate training needs, and doesn't reduce policy requirements.
Which of the following BEST describes the purpose of a security policy?
A) To define acceptable use and security requirements
B) To manage hardware inventory
C) To increase system speed
D) To replace the need for training
Answer: A) To define acceptable use and security requirements
Security policies establish organizational security standards and expectations. They don't manage inventory, increase speed, or replace training.
Which of the following BEST describes the purpose of a vulnerability scanner?
A) To identify and report potential security weaknesses
B) To block malicious traffic in real time
C) To encrypt all data on the network
D) To manage user accounts
Answer: A) To identify and report potential security weaknesses
Vulnerability scanners scan systems to find known vulnerabilities. They don't block traffic, encrypt data, or manage accounts.
Which of the following BEST describes the purpose of a business impact analysis (BIA)?
A) To identify critical systems and their recovery priorities
B) To manage employee schedules
C) To install new software
D) To replace the need for backups
Answer: A) To identify critical systems and their recovery priorities
BIA determines which systems are most critical and how quickly they must be restored. It doesn't manage schedules, install software, or replace backups.
Which of the following BEST describes the purpose of a risk register?
A) To track and manage identified risks and mitigation strategies
B) To store employee passwords
C) To manage backup schedules
D) To replace the need for audits
Answer: A) To track and manage identified risks and mitigation strategies
A risk register documents risks, their likelihood, impact, and planned responses. It doesn't store passwords, manage backups, or replace audits.
Which of the following BEST describes the purpose of a security awareness program?
A) To educate users about security risks and best practices
B) To replace the need for firewalls
C) To install software updates
D) To manage employee benefits
Answer: A) To educate users about security risks and best practices
Security awareness programs train users to recognize threats and follow security procedures. They don't replace firewalls, install updates, or manage benefits.
Which of the following BEST describes the purpose of a honeypot?
A) To attract and detect attackers by mimicking a vulnerable system
B) To encrypt all user data
C) To block all incoming traffic
D) To manage user passwords
Answer: A) To attract and detect attackers by mimicking a vulnerable system
Honeypots are decoy systems designed to detect and study attacker behavior. They don't encrypt data, block traffic, or manage passwords.
Which of the following BEST describes the purpose of a digital signature?
A) To ensure data integrity and non-repudiation
B) To encrypt data for confidentiality
C) To compress large files
D) To authenticate users via biometrics
Answer: A) To ensure data integrity and non-repudiation
Digital signatures use cryptographic techniques to verify that data has not been altered and to prove the sender's identity, providing both integrity and non-repudiation. While encryption ensures confidentiality, digital signatures focus on authenticity and integrity verification, not compression, and they're not related to biometric authentication.
Which of the following BEST describes the purpose of a security patch?
A) To fix known vulnerabilities in software or systems
B) To improve system performance
C) To increase user permissions
D) To disable antivirus software
Answer: A) To fix known vulnerabilities in software or systems
A security patch addresses specific security flaws discovered in software. It doesn't improve performance, increase permissions, or disable security software.
Which of the following BEST describes the purpose of a firewall rule that blocks all traffic by default?
A) To follow the principle of least privilege and reduce attack surface
B) To improve network speed
C) To allow all internal traffic
D) To disable logging
Answer: A) To follow the principle of least privilege and reduce attack surface
Firewall rules that block all traffic by default implement the principle of least privilege, allowing only explicitly permitted traffic. This reduces the attack surface. It doesn't improve speed, allows internal traffic, or disables logging.
Which of the following BEST describes the purpose of a security incident?
A) Any event that threatens the confidentiality, integrity, or availability of information
B) A system reboot
C) A user changing their password
D) A software update
Answer: A) Any event that threatens the confidentiality, integrity, or availability of information
A security incident includes any event that compromises information security. Routine operations like reboots and password changes aren't incidents, and software updates are normal maintenance.
Which of the following BEST describes the purpose of a recovery point objective (RPO)?
A) The maximum acceptable amount of data loss measured in time
B) The maximum acceptable downtime
C) The time to restore a system after failure
D) The number of backup copies
Answer: A) The maximum acceptable amount of data loss measured in time
RPO defines how much data loss is acceptable based on time intervals. RTO is maximum downtime, restoration time is different from data loss, and backup count is a separate metric.
Which of the following BEST describes the purpose of a change control board (CCB)?
A) To approve or reject changes to systems to maintain stability and security
B) To manage user passwords
C) To install software updates
D) To block all network traffic
Answer: A) To approve or reject changes to systems to maintain stability and security
The CCB reviews and approves system changes to ensure they don't introduce vulnerabilities or destabilize operations. It doesn't manage passwords, install updates, or block traffic.
Which of the following BEST describes the purpose of a business continuity plan (BCP)?
A) To ensure that critical systems can be restored after a disruption
B) To prevent all cyberattacks
C) To replace the need for backups
D) To manage employee salaries
Answer: A) To ensure that critical systems can be restored after a disruption
A BCP outlines procedures to maintain or quickly resume critical business operations during disruptions. It doesn't prevent all attacks, doesn't replace backups, and isn't related to salary management.
Which of the following BEST describes the purpose of a security baseline configuration?
A) To establish minimum security requirements for systems
B) To maximize system performance
C) To disable all security features
D) To allow unlimited user access
Answer: A) To establish minimum security requirements for systems
Security baselines define the minimum acceptable security configuration for systems to reduce vulnerabilities. They don't maximize performance, disable security, or allow unlimited access.
Which of the following BEST describes the purpose of a security policy?
A) To define acceptable behavior and security requirements
B) To manage hardware inventory
C) To increase system performance
D) To replace the need for training
Answer: A) To define acceptable behavior and security requirements
Security policies establish organizational security standards and expectations. They don't manage inventory, increase performance, or replace training.
Which of the following BEST describes the purpose of a security awareness program?
A) To educate users about security risks and best practices
B) To install antivirus software
C) To manage employee payroll
D) To replace the need for firewalls
Answer: A) To educate users about security risks and best practices
Security awareness programs train users to recognize threats and follow security procedures. They don't install software, manage payroll, or replace firewalls.
Which of the following BEST describes the purpose of a security audit?
A) To evaluate compliance with security policies and identify gaps
B) To replace the need for training
C) To manage employee payroll
D) To install software updates
Answer: A) To evaluate compliance with security policies and identify gaps
Security audits assess adherence to policies and identify deficiencies. They don't replace training, manage payroll, or install updates.
Which of the following BEST describes the purpose of a vulnerability assessment?
A) To identify and report potential security weaknesses
B) To exploit vulnerabilities in a system
C) To block all network traffic
D) To encrypt all data
Answer: A) To identify and report potential security weaknesses
Vulnerability assessments scan systems to find weaknesses. They don't exploit vulnerabilities, block traffic, or encrypt data.
Which of the following BEST describes the purpose of a risk assessment?
A) To identify threats, vulnerabilities, and potential impacts
B) To install antivirus software
C) To manage employee benefits
D) To replace the need for backups
Answer: A) To identify threats, vulnerabilities, and potential impacts
Risk assessments systematically identify potential risks to inform security decisions. They don't install software, manage benefits, or replace backups.
Which of the following BEST describes the purpose of a security incident response plan?
A) To provide a structured approach for handling security incidents
B) To prevent all security incidents from occurring
C) To eliminate the need for security training
D) To reduce the number of security policies
Answer: A) To provide a structured approach for handling security incidents
A security incident response plan establishes clear procedures for detecting, analyzing, containing, eradicating, and recovering from security incidents. It doesn't prevent all incidents (which is impossible), doesn't eliminate training needs, and doesn't reduce policy requirements.
Which of the following BEST describes the purpose of a security baseline?
A) To provide a standard configuration for systems to reduce vulnerabilities
B) To allow all users full access to all systems
C) To increase system performance
D) To replace the need for firewalls
Answer: A) To provide a standard configuration for systems to reduce vulnerabilities
A security baseline establishes minimum security requirements for systems, ensuring consistent configuration that reduces known vulnerabilities. It doesn't grant unlimited access, doesn't necessarily improve performance, and doesn't eliminate the need for other security controls like firewalls.
Which of the following BEST describes the purpose of a digital certificate?
A) To verify the identity of a website or user
B) To encrypt data at rest
C) To manage user accounts
D) To block spam emails
Answer: A) To verify the identity of a website or user
Digital certificates use public key infrastructure to authenticate identities. They don't encrypt data at rest, manage accounts, or block spam.
Which of the following BEST describes the purpose of a security patch?
A) To fix known vulnerabilities in software or systems
B) To improve system performance
C) To increase user permissions
D) To disable antivirus software
Answer: A) To fix known vulnerabilities in software or systems
A security patch addresses specific security flaws discovered in software. It doesn't improve performance, increase permissions, or disable security software.
Which of the following BEST describes the purpose of a firewall rule that blocks all traffic by default?
A) To follow the principle of least privilege and reduce attack surface
B) To improve network speed
C) To allow all internal traffic
D) To disable logging
Answer: A) To follow the principle of least privilege and reduce attack surface
Firewall rules that block all traffic by default implement the principle of least privilege, allowing only explicitly permitted traffic. This reduces the attack surface. It doesn't improve speed, allows internal traffic, or disables logging.
Which of the following BEST describes the purpose of a security incident?
A) Any event that threatens the confidentiality, integrity, or availability of information
B) A system reboot
C) A user changing their password
D) A software update
Answer: A) Any event that threatens the confidentiality, integrity, or availability of information
A security incident includes any event that compromises information security. Routine operations like reboots and password changes aren't incidents, and software updates are normal maintenance.
Which of the following BEST describes the purpose of a recovery point objective (RPO)?
A) The maximum acceptable amount of data loss measured in time
B) The maximum acceptable downtime
C) The time to restore a system after failure
D) The number of backup copies
Answer: A) The maximum acceptable amount of data loss measured in time
RPO defines how much data loss is acceptable based on time intervals. RTO is maximum downtime, restoration time is different from data loss, and backup count is a separate metric.
Which of the following BEST describes the purpose of a change control board (CCB)?
A) To approve or reject changes to systems to maintain stability and security
B) To manage user passwords
C) To install software updates
D) To block all network traffic
Answer: A) To approve or reject changes to systems to maintain stability and security
The CCB reviews and approves system changes to ensure they don't introduce vulnerabilities or destabilize operations. It doesn't manage passwords, install updates, or block traffic.
Which of the following BEST describes the purpose of a business continuity plan (BCP)?
A) To ensure that critical systems can be restored after a disruption
B) To prevent all cyberattacks
C) To replace the need for backups
D) To manage employee salaries
Answer: A) To ensure that critical systems can be restored after a disruption
A BCP outlines procedures to maintain or quickly resume critical business operations during disruptions. It doesn't prevent all attacks, doesn't replace backups, and isn't related to salary management.
Which of the following BEST describes the purpose of a security baseline configuration?
A) To establish minimum security requirements for systems
B) To maximize system performance
C) To disable all security features
D) To allow unlimited user access
Answer: A) To establish minimum security requirements for systems
Security baselines define the minimum acceptable security configuration for systems to reduce vulnerabilities. They don't maximize performance, disable security, or allow unlimited access.
Which of the following BEST describes the purpose of a security policy?
A) To define acceptable behavior and security requirements
B) To manage hardware inventory
C) To increase system performance
D) To replace the need for training
Answer: A) To define acceptable behavior and security requirements
Security policies establish organizational security standards and expectations. They don't manage inventory, increase performance, or replace training.
Which of the following BEST describes the purpose of a security awareness program?
A) To educate users about security risks and best practices
B) To install antivirus software
C) To manage employee payroll
D) To replace the need for firewalls
Answer: A) To educate users about security risks and best practices
Security awareness programs train users to recognize threats and follow security procedures. They don't install software, manage payroll, or replace firewalls.
Which of the following BEST describes the purpose of a security audit?
A) To evaluate compliance with security policies and identify gaps
B) To replace the need for training
C) To manage employee payroll
D) To install software updates
Answer: A) To evaluate compliance with security policies and identify gaps
Security audits assess adherence to policies and identify deficiencies. They don't replace training, manage payroll, or install updates.
Which of the following BEST describes the purpose of a vulnerability assessment?
A) To identify and report potential security weaknesses
B) To exploit vulnerabilities in a system
C) To block all network traffic
D) To encrypt all data
Answer: A) To identify and report potential security weaknesses
Vulnerability assessments scan systems to find weaknesses. They don't exploit vulnerabilities, block traffic, or encrypt data.
Which of the following BEST describes the purpose of a risk assessment?
A) To identify threats, vulnerabilities, and potential impacts
B) To install antivirus software
C) To manage employee benefits
D) To replace the need for backups
Answer: A) To identify threats, vulnerabilities, and potential impacts
Risk assessments systematically identify potential risks to inform security decisions. They don't install software, manage benefits, or replace backups.
Which of the following BEST describes the purpose of a security incident response plan?
A) To provide a structured approach for handling security incidents
B) To prevent all security incidents from occurring
C) To eliminate the need for security training
D) To reduce the number of security policies
Answer: A) To provide a structured approach for handling security incidents
A security incident response plan establishes clear procedures for detecting, analyzing, containing, eradicating, and recovering from security incidents. It doesn't prevent all incidents (which is impossible), doesn't eliminate training needs, and doesn't reduce policy requirements.
Which of the following BEST describes the purpose of a security baseline?
A) To provide a standard configuration for systems to reduce vulnerabilities
B) To allow all users full access to all systems
C) To increase system performance
D) To replace the need for firewalls
Answer: A) To provide a standard configuration for systems to reduce vulnerabilities
A security baseline establishes minimum security requirements for systems, ensuring consistent configuration that reduces known vulnerabilities. It doesn't grant unlimited access, doesn't necessarily improve performance, and doesn't eliminate the need for other security controls like firewalls.
Which of the following BEST describes the purpose of a digital certificate?
A) To verify the identity of a website or user
B) To encrypt data at rest
C) To manage user accounts
D) To block spam emails
Answer: A) To verify the identity of a website or user
Digital certificates use public key infrastructure to authenticate identities. They don't encrypt data at rest, manage accounts, or block spam.
Which of the following is the PRIMARY purpose of a security incident response plan?
A) To prevent all security incidents from occurring
B) To provide a structured approach for handling security incidents
C) To eliminate the need for security training
D) To reduce the number of security policies
Answer: B) To provide a structured approach for handling security incidents
A security incident response plan establishes clear procedures for detecting, analyzing, containing, eradicating, and recovering from security incidents. It doesn't prevent all incidents (which is impossible), doesn't eliminate training needs, and doesn't reduce policy requirements.
A company is implementing a new security policy that requires all users to undergo annual security training. This is an example of which type of control?
A) Preventive
B) Detective
C) Corrective
D) Deterrent
Answer: A) Preventive
Preventive controls aim to stop incidents before they occur. Annual security training helps prevent security incidents by educating users about threats and best practices. Detective controls identify issues after they happen, corrective controls address problems after discovery, and deterrent controls discourage unwanted behavior but don't prevent it directly.
Which of the following BEST describes the purpose of a security baseline configuration?
A) To establish minimum security requirements for systems
B) To maximize system performance
C) To disable all security features
D) To allow unlimited user access
Answer: A) To establish minimum security requirements for systems
Security baselines define the minimum acceptable security configuration for systems to reduce vulnerabilities. They don't maximize performance, disable security, or allow unlimited access.
A security analyst is investigating a potential data breach and discovers that an employee's account was used to access sensitive files. Which of the following should be investigated FIRST?
A) The employee's recent password changes
B) The employee's network access logs
C) The employee's physical access records
D) The employee's email communications
Answer: B) The employee's network access logs
Network access logs show when and how the account was accessed, helping determine if it was legitimate or compromised. Password changes don't reveal access patterns, physical access isn't relevant to digital breaches, and email communications are secondary evidence.
Which of the following is the MOST effective method to protect against cross-site scripting (XSS) attacks?
A) Using strong passwords
B) Implementing input validation and sanitization
C) Installing antivirus software
D) Disabling JavaScript in browsers
Answer: B) Implementing input validation and sanitization
Input validation and sanitization prevent malicious script code from being executed by removing or escaping dangerous characters. Strong passwords don't prevent XSS, antivirus software detects malware but not XSS, and disabling JavaScript breaks many legitimate websites.
A company wants to ensure that its data is protected both at rest and in transit. Which of the following encryption methods should be used for each?
A) AES for data at rest, TLS for data in transit
B) RSA for data at rest, SSL for data in transit
C) SHA-256 for data at rest, IPsec for data in transit
D) DES for data at rest, WPA3 for data in transit
Answer: A) AES for data at rest, TLS for data in transit
AES is a symmetric encryption algorithm ideal for protecting data at rest. TLS is the standard protocol for securing data in transit. RSA is asymmetric encryption better for key exchange, SHA-256 is hashing not encryption, DES is outdated and insecure, WPA3 is wireless encryption.
Which of the following is a PRIMARY benefit of using a SIEM (Security Information and Event Management) system?
A) To block all malicious traffic in real time
B) To centralize and correlate security logs for analysis and alerting
C) To manage user passwords
D) To encrypt all data at rest
Answer: B) To centralize and correlate security logs for analysis and alerting
SIEM systems collect, analyze, and correlate log data from multiple sources to identify security events and generate alerts. They don't block traffic, manage passwords, or encrypt data.
Which of the following BEST describes a security incident?
A) Any event that could potentially threaten information security
B) A system reboot
C) A user changing their password
D) A software update
Answer: A) Any event that could potentially threaten information security
A security incident includes any event that compromises confidentiality, integrity, or availability of information. Routine operations like reboots and password changes aren't incidents, and software updates are normal maintenance.
A company is implementing a new authentication system that requires users to provide a password and a fingerprint scan. This is an example of:
A) Single-factor authentication
B) Two-factor authentication (2FA)
C) Multi-factor authentication (MFA)
D) Biometric authentication
Answer: C) Multi-factor authentication (MFA)
MFA uses two or more authentication factors from different categories. Password + fingerprint represents two factors (something you know + something you are). 2FA is a subset of MFA, and biometric authentication is just one factor category.
Which of the following is the MOST effective way to prevent data leakage through email?
A) Use strong passwords
B) Implement data loss prevention (DLP)
C) Disable all email accounts
D) Use only internal messaging
Answer: B) Implement data loss prevention (DLP)
DLP systems monitor and control email content to prevent unauthorized data transfer. Strong passwords don't prevent email leakage, disabling email is impractical, and internal messaging alone isn't sufficient protection.
Which of the following BEST describes the purpose of a risk assessment?
A) To identify threats, vulnerabilities, and potential impacts
B) To install antivirus software
C) To manage employee benefits
D) To replace the need for backups
Answer: A) To identify threats, vulnerabilities, and potential impacts
Risk assessments systematically identify potential risks to inform security decisions. They don't install software, manage benefits, or replace backups.
A security administrator wants to ensure that only specific devices can connect to the wireless network. Which of the following is the BEST control?
A) MAC filtering
B) WPA3 encryption
C) Strong passwords
D) Firewall rules
Answer: A) MAC filtering
MAC filtering restricts network access to specific hardware addresses. WPA3 provides wireless encryption, strong passwords are for authentication, and firewall rules control network traffic but don't restrict specific devices.
Which of the following is a PRIMARY purpose of a security policy?
A) To define acceptable behavior and security requirements
B) To manage hardware inventory
C) To increase system performance
D) To replace the need for training
Answer: A) To define acceptable behavior and security requirements
Security policies establish organizational security standards and expectations. They don't manage inventory, increase performance, or replace training.
Which of the following BEST describes the purpose of a security awareness program?
A) To educate users about security risks and best practices
B) To install antivirus software
C) To manage employee payroll
D) To replace the need for firewalls
Answer: A) To educate users about security risks and best practices
Security awareness programs train users to recognize threats and follow security procedures. They don't install software, manage payroll, or replace firewalls.
A security analyst discovers that a system has been compromised and is communicating with a known malicious IP address. Which of the following should be done FIRST?
A) Reinstall the operating system
B) Disconnect the system from the network
C) Notify the user
D) Change the password
Answer: B) Disconnect the system from the network
Immediate network disconnection prevents further communication with attackers and limits damage. Reinstalling OS is premature, notifying the user may alert the attacker, and changing passwords isn't the immediate priority.
Which of the following is the BEST method to verify the integrity of a downloaded file?
A) Check the file size
B) Compare the file's hash value with the published hash
C) Open the file to see if it works
D) Scan it with antivirus software
Answer: B) Compare the file's hash value with the published hash
Hash values provide cryptographic verification of file integrity. File size checks are unreliable, opening files can be dangerous, and antivirus scanning detects malware but doesn't verify file integrity.
Which of the following is a PRIMARY benefit of using a secure boot process?
A) To prevent unauthorized firmware from loading
B) To increase system speed
C) To allow all software to run
D) To disable encryption
Answer: A) To prevent unauthorized firmware from loading
Secure boot verifies the integrity of boot components to ensure only trusted software runs. It doesn't increase speed, allows all software, or disables encryption.
Which of the following BEST describes a false negative in security monitoring?
A) A legitimate activity being flagged as malicious
B) A malicious activity going undetected
C) A system crash during a scan
D) A user forgetting their password
Answer: B) A malicious activity going undetected
False negatives occur when threats are missed by detection systems. False positives flag legitimate activities as threats. System crashes and password issues are unrelated to detection accuracy.
A company is concerned about employees downloading unauthorized software. Which of the following is the BEST solution?
A) Use a firewall
B) Implement application whitelisting
C) Disable all internet access
D) Install antivirus software only
Answer: B) Implement application whitelisting
Application whitelisting allows only approved software to run. Firewalls control network traffic, disabling internet access is impractical, and antivirus software detects but doesn't prevent unauthorized downloads.
Which of the following is the MOST secure method for transmitting sensitive data over the internet?
A) HTTP
B) FTP
C) TLS
D) SMTP
Answer: C) TLS
TLS provides encryption and authentication for secure communication. HTTP and FTP transmit data in plaintext, SMTP is for email transmission, not secure data transfer.
Which of the following is a PRIMARY purpose of a vulnerability scanner?
A) To block malicious traffic in real time
B) To identify and report potential security weaknesses
C) To encrypt all data on the network
D) To manage user accounts
Answer: B) To identify and report potential security weaknesses
Vulnerability scanners scan systems to find known vulnerabilities. They don't block traffic, encrypt data, or manage accounts.
Which of the following BEST describes a threat actor who targets high-profile individuals such as CEOs?
A) Script kiddie
B) Nation-state
C) Whistleblower
D) Executive-level target (whaling)
Answer: D) Executive-level target (whaling)
Whaling specifically refers to targeting high-value individuals like executives. Script kiddies are unskilled attackers, nation-states are state-sponsored actors, and whistleblowers are individuals exposing wrongdoing.
A company wants to ensure that its data backups are secure and recoverable. Which of the following is the MOST important factor to consider?
A) Backup frequency
B) Storage location and encryption
C) Number of backup copies
D) Backup software version
Answer: B) Storage location and encryption
The security and accessibility of backups depend most critically on where they're stored and how well they're encrypted. While backup frequency and quantity matter, storage location and encryption prevent unauthorized access and data compromise.
Which of the following is the BEST way to protect against credential stuffing attacks?
A) Implementing strong password policies
B) Enabling multi-factor authentication (MFA)
C) Using a password manager
D) Disabling account lockout
Answer: B) Enabling multi-factor authentication (MFA)
Credential stuffing attacks reuse leaked credentials across multiple sites. MFA provides additional security layers beyond just passwords, making it much harder for attackers to gain access even if they have valid credentials. Strong password policies alone don't prevent credential reuse, password managers help manage passwords but don't stop credential stuffing, and disabling account lockout actually makes the system more vulnerable.
Which of the following is a PRIMARY purpose of a business continuity plan (BCP)?
A) To ensure that critical systems can be restored after a disruption
B) To prevent all cyberattacks
C) To replace the need for backups
D) To manage employee salaries
Answer: A) To ensure that critical systems can be restored after a disruption
A BCP outlines procedures to maintain or quickly resume critical business operations during disruptions. It doesn't prevent all attacks, doesn't replace backups, and isn't related to salary management.
Which of the following BEST describes the purpose of a digital certificate?
A) To encrypt data at rest
B) To verify the identity of a website or user
C) To manage user accounts
D) To block spam emails
Answer: B) To verify the identity of a website or user
Digital certificates use public key infrastructure to authenticate identities. They don't encrypt data at rest, manage accounts, or block spam.
A company is implementing a new system and wants to ensure that it is secure from the start. Which of the following is the BEST approach?
A) Add security controls after deployment
B) Use a secure development lifecycle (SDLC)
C) Rely on third-party testing only
D) Disable all security features to improve performance
Answer: B) Use a secure development lifecycle (SDLC)
SDLC integrates security throughout the development process. Adding controls after deployment is less effective, relying only on third-party testing leaves gaps, and disabling security features creates vulnerabilities.
Which of the following is a PRIMARY benefit of using a cloud access security broker (CASB)?
A) To manage physical access to data centers
B) To enforce security policies across cloud services
C) To replace the need for firewalls
D) To increase internet speed
Answer: B) To enforce security policies across cloud services
CASBs provide visibility and control over cloud service usage. They don't manage physical access, don't replace firewalls, and don't improve internet speed.
Which of the following BEST describes a security baseline?
A) To provide a standard configuration for systems to reduce vulnerabilities
B) To allow all users full access to all systems
C) To increase system performance
D) To replace the need for firewalls
Answer: A) To provide a standard configuration for systems to reduce vulnerabilities
A security baseline establishes minimum security requirements for systems, ensuring consistent configuration that reduces known vulnerabilities. It doesn't grant unlimited access, doesn't necessarily improve performance, and doesn't eliminate the need for other security controls like firewalls.
Which of the following is the BEST way to protect against social engineering attacks?
A) Use strong passwords
B) Conduct regular security awareness training
C) Disable all email
D) Use only wired connections
Answer: B) Conduct regular security awareness training
Training helps users recognize and avoid social engineering tactics. Strong passwords don't prevent manipulation, disabling email is impractical, and wired connections don't address social engineering.
Which of the following BEST describes the purpose of a security audit?
A) To evaluate compliance with security policies and identify gaps
B) To replace the need for training
C) To manage employee payroll
D) To install software updates
Answer: A) To evaluate compliance with security policies and identify gaps
Security audits assess adherence to policies and identify deficiencies. They don't replace training, manage payroll, or install updates.
Which of the following is a PRIMARY purpose of a disaster recovery plan (DRP)?
A) To ensure that critical systems can be restored after a disruption
B) To prevent all cyberattacks
C) To replace the need for backups
D) To manage employee schedules
Answer: A) To ensure that critical systems can be restored after a disruption
A DRP outlines procedures to restore systems and data after disasters. It doesn't prevent all attacks, doesn't replace backups, and isn't related to schedule management.
Which of the following BEST describes the purpose of a security incident response plan?
A) To provide a structured approach for handling security incidents
B) To prevent all security incidents from occurring
C) To eliminate the need for security training
D) To reduce the number of security policies
Answer: A) To provide a structured approach for handling security incidents
A security incident response plan establishes clear procedures for detecting, analyzing, containing, eradicating, and recovering from security incidents. It doesn't prevent all incidents (which is impossible), doesn't eliminate training needs, and doesn't reduce policy requirements.
Which of the following BEST describes the purpose of a security policy?
A) To define acceptable use and security requirements
B) To manage hardware inventory
C) To increase system speed
D) To replace the need for training
Answer: A) To define acceptable use and security requirements
Security policies establish organizational security standards and expectations. They don't manage inventory, increase speed, or replace training.
Which of the following BEST describes the purpose of a vulnerability scanner?
A) To identify and report potential security weaknesses
B) To block malicious traffic in real time
C) To encrypt all data on the network
D) To manage user accounts
Answer: A) To identify and report potential security weaknesses
Vulnerability scanners scan systems to find known vulnerabilities. They don't block traffic, encrypt data, or manage accounts.
Which of the following BEST describes the purpose of a business impact analysis (BIA)?
A) To identify critical systems and their recovery priorities
B) To manage employee schedules
C) To install new software
D) To replace the need for backups
Answer: A) To identify critical systems and their recovery priorities
BIA determines which systems are most critical and how quickly they must be restored. It doesn't manage schedules, install software, or replace backups.
Which of the following BEST describes the purpose of a risk register?
A) To track and manage identified risks and mitigation strategies
B) To store employee passwords
C) To manage backup schedules
D) To replace the need for audits
Answer: A) To track and manage identified risks and mitigation strategies
A risk register documents risks, their likelihood, impact, and planned responses. It doesn't store passwords, manage backups, or replace audits.
Which of the following BEST describes the purpose of a security awareness program?
A) To educate users about security risks and best practices
B) To replace the need for firewalls
C) To install software updates
D) To manage employee benefits
Answer: A) To educate users about security risks and best practices
Security awareness programs train users to recognize threats and follow security procedures. They don't replace firewalls, install updates, or manage benefits.
Which of the following BEST describes the purpose of a honeypot?
A) To attract and detect attackers by mimicking a vulnerable system
B) To encrypt all user data
C) To block all incoming traffic
D) To manage user passwords
Answer: A) To attract and detect attackers by mimicking a vulnerable system
Honeypots are decoy systems designed to detect and study attacker behavior. They don't encrypt data, block traffic, or manage passwords.
Which of the following BEST describes the purpose of a digital signature?
A) To ensure data integrity and non-repudiation
B) To encrypt data for confidentiality
C) To compress large files
D) To authenticate users via biometrics
Answer: A) To ensure data integrity and non-repudiation
Digital signatures use cryptographic techniques to verify that data has not been altered and to prove the sender's identity, providing both integrity and non-repudiation. While encryption ensures confidentiality, digital signatures focus on authenticity and integrity verification, not compression, and they're not related to biometric authentication.
Which of the following BEST describes the purpose of a security patch?
A) To fix known vulnerabilities in software or systems
B) To improve system performance
C) To increase user permissions
D) To disable antivirus software
Answer: A) To fix known vulnerabilities in software or systems
A security patch addresses specific security flaws discovered in software. It doesn't improve performance, increase permissions, or disable security software.
Which of the following BEST describes the purpose of a firewall rule that blocks all traffic by default?
A) To follow the principle of least privilege and reduce attack surface
B) To improve network speed
C) To allow all internal traffic
D) To disable logging
Answer: A) To follow the principle of least privilege and reduce attack surface
Firewall rules that block all traffic by default implement the principle of least privilege, allowing only explicitly permitted traffic. This reduces the attack surface. It doesn't improve speed, allows internal traffic, or disables logging.
Which of the following BEST describes the purpose of a security incident?
A) Any event that threatens the confidentiality, integrity, or availability of information
B) A system reboot
C) A user changing their password
D) A software update
Answer: A) Any event that threatens the confidentiality, integrity, or availability of information
A security incident includes any event that compromises information security. Routine operations like reboots and password changes aren't incidents, and software updates are normal maintenance.
Which of the following BEST describes the purpose of a recovery point objective (RPO)?
A) The maximum acceptable amount of data loss measured in time
B) The maximum acceptable downtime
C) The time to restore a system after failure
D) The number of backup copies
Answer: A) The maximum acceptable amount of data loss measured in time
RPO defines how much data loss is acceptable based on time intervals. RTO is maximum downtime, restoration time is different from data loss, and backup count is a separate metric.
Which of the following BEST describes the purpose of a change control board (CCB)?
A) To approve or reject changes to systems to maintain stability and security
B) To manage user passwords
C) To install software updates
D) To block all network traffic
Answer: A) To approve or reject changes to systems to maintain stability and security
The CCB reviews and approves system changes to ensure they don't introduce vulnerabilities or destabilize operations. It doesn't manage passwords, install updates, or block traffic.
Which of the following BEST describes the purpose of a business continuity plan (BCP)?
A) To ensure that critical systems can be restored after a disruption
B) To prevent all cyberattacks
C) To replace the need for backups
D) To manage employee salaries
Answer: A) To ensure that critical systems can be restored after a disruption
A BCP outlines procedures to maintain or quickly resume critical business operations during disruptions. It doesn't prevent all attacks, doesn't replace backups, and isn't related to salary management.
Which of the following BEST describes the purpose of a security baseline configuration?
A) To establish minimum security requirements for systems
B) To maximize system performance
C) To disable all security features
D) To allow unlimited user access
Answer: A) To establish minimum security requirements for systems
Security baselines define the minimum acceptable security configuration for systems to reduce vulnerabilities. They don't maximize performance, disable security, or allow unlimited access.
Which of the following BEST describes the purpose of a security policy?
A) To define acceptable behavior and security requirements
B) To manage hardware inventory
C) To increase system performance
D) To replace the need for training
Answer: A) To define acceptable behavior and security requirements
Security policies establish organizational security standards and expectations. They don't manage inventory, increase performance, or replace training.
Which of the following BEST describes the purpose of a security awareness program?
A) To educate users about security risks and best practices
B) To install antivirus software
C) To manage employee payroll
D) To replace the need for firewalls
Answer: A) To educate users about security risks and best practices
Security awareness programs train users to recognize threats and follow security procedures. They don't install software, manage payroll, or replace firewalls.
Which of the following BEST describes the purpose of a security audit?
A) To evaluate compliance with security policies and identify gaps
B) To replace the need for training
C) To manage employee payroll
D) To install software updates
Answer: A) To evaluate compliance with security policies and identify gaps
Security audits assess adherence to policies and identify deficiencies. They don't replace training, manage payroll, or install updates.
Which of the following BEST describes the purpose of a vulnerability assessment?
A) To identify and report potential security weaknesses
B) To exploit vulnerabilities in a system
C) To block all network traffic
D) To encrypt all data
Answer: A) To identify and report potential security weaknesses
Vulnerability assessments scan systems to find weaknesses. They don't exploit vulnerabilities, block traffic, or encrypt data.
Which of the following BEST describes the purpose of a risk assessment?
A) To identify threats, vulnerabilities, and potential impacts
B) To install antivirus software
C) To manage employee benefits
D) To replace the need for backups
Answer: A) To identify threats, vulnerabilities, and potential impacts
Risk assessments systematically identify potential risks to inform security decisions. They don't install software, manage benefits, or replace backups.
Which of the following BEST describes the purpose of a security incident response plan?
A) To provide a structured approach for handling security incidents
B) To prevent all security incidents from occurring
C) To eliminate the need for security training
D) To reduce the number of security policies
Answer: A) To provide a structured approach for handling security incidents
A security incident response plan establishes clear procedures for detecting, analyzing, containing, eradicating, and recovering from security incidents. It doesn't prevent all incidents (which is impossible), doesn't eliminate training needs, and doesn't reduce policy requirements.
Which of the following BEST describes the purpose of a security baseline?
A) To provide a standard configuration for systems to reduce vulnerabilities
B) To allow all users full access to all systems
C) To increase system performance
D) To replace the need for firewalls
Answer: A) To provide a standard configuration for systems to reduce vulnerabilities
A security baseline establishes minimum security requirements for systems, ensuring consistent configuration that reduces known vulnerabilities. It doesn't grant unlimited access, doesn't necessarily improve performance, and doesn't eliminate the need for other security controls like firewalls.
Which of the following BEST describes the purpose of a digital certificate?
A) To verify the identity of a website or user
B) To encrypt data at rest
C) To manage user accounts
D) To block spam emails
Answer: A) To verify the identity of a website or user
Digital certificates use public key infrastructure to authenticate identities. They don't encrypt data at rest, manage accounts, or block spam.
Which of the following BEST describes the purpose of a security patch?
A) To fix known vulnerabilities in software or systems
B) To improve system performance
C) To increase user permissions
D) To disable antivirus software
Answer: A) To fix known vulnerabilities in software or systems
A security patch addresses specific security flaws discovered in software. It doesn't improve performance, increase permissions, or disable security software.
Which of the following BEST describes the purpose of a firewall rule that blocks all traffic by default?
A) To follow the principle of least privilege and reduce attack surface
B) To improve network speed
C) To allow all internal traffic
D) To disable logging
Answer: A) To follow the principle of least privilege and reduce attack surface
Firewall rules that block all traffic by default implement the principle of least privilege, allowing only explicitly permitted traffic. This reduces the attack surface. It doesn't improve speed, allows internal traffic, or disables logging.
Which of the following BEST describes the purpose of a security incident?
A) Any event that threatens the confidentiality, integrity, or availability of information
B) A system reboot
C) A user changing their password
D) A software update
Answer: A) Any event that threatens the confidentiality, integrity, or availability of information
A security incident includes any event that compromises information security. Routine operations like reboots and password changes aren't incidents, and software updates are normal maintenance.
Which of the following BEST describes the purpose of a recovery point objective (RPO)?
A) The maximum acceptable amount of data loss measured in time
B) The maximum acceptable downtime
C) The time to restore a system after failure
D) The number of backup copies
Answer: A) The maximum acceptable amount of data loss measured in time
RPO defines how much data loss is acceptable based on time intervals. RTO is maximum downtime, restoration time is different from data loss, and backup count is a separate metric.
Which of the following BEST describes the purpose of a change control board (CCB)?
A) To approve or reject changes to systems to maintain stability and security
B) To manage user passwords
C) To install software updates
D) To block all network traffic
Answer: A) To approve or reject changes to systems to maintain stability and security
The CCB reviews and approves system changes to ensure they don't introduce vulnerabilities or destabilize operations. It doesn't manage passwords, install updates, or block traffic.
Which of the following BEST describes the purpose of a business continuity plan (BCP)?
A) To ensure that critical systems can be restored after a disruption
B) To prevent all cyberattacks
C) To replace the need for backups
D) To manage employee salaries
Answer: A) To ensure that critical systems can be restored after a disruption
A BCP outlines procedures to maintain or quickly resume critical business operations during disruptions. It doesn't prevent all attacks, doesn't replace backups, and isn't related to salary management.
Which of the following BEST describes the purpose of a security baseline configuration?
A) To establish minimum security requirements for systems
B) To maximize system performance
C) To disable all security features
D) To allow unlimited user access
Answer: A) To establish minimum security requirements for systems
Security baselines define the minimum acceptable security configuration for systems to reduce vulnerabilities. They don't maximize performance, disable security, or allow unlimited access.
Which of the following BEST describes the purpose of a security policy?
A) To define acceptable behavior and security requirements
B) To manage hardware inventory
C) To increase system performance
D) To replace the need for training
Answer: A) To define acceptable behavior and security requirements
Security policies establish organizational security standards and expectations. They don't manage inventory, increase performance, or replace training.
Which of the following BEST describes the purpose of a security awareness program?
A) To educate users about security risks and best practices
B) To install antivirus software
C) To manage employee payroll
D) To replace the need for firewalls
Answer: A) To educate users about security risks and best practices
Security awareness programs train users to recognize threats and follow security procedures. They don't install software, manage payroll, or replace firewalls.
Which of the following BEST describes the purpose of a security audit?
A) To evaluate compliance with security policies and identify gaps
B) To replace the need for training
C) To manage employee payroll
D) To install software updates
Answer: A) To evaluate compliance with security policies and identify gaps
Security audits assess adherence to policies and identify deficiencies. They don't replace training, manage payroll, or install updates.
Which of the following BEST describes the purpose of a vulnerability assessment?
A) To identify and report potential security weaknesses
B) To exploit vulnerabilities in a system
C) To block all network traffic
D) To encrypt all data
Answer: A) To identify and report potential security weaknesses
Vulnerability assessments scan systems to find weaknesses. They don't exploit vulnerabilities, block traffic, or encrypt data.
Which of the following BEST describes the purpose of a risk assessment?
A) To identify threats, vulnerabilities, and potential impacts
B) To install antivirus software
C) To manage employee benefits
D) To replace the need for backups
Answer: A) To identify threats, vulnerabilities, and potential impacts
Risk assessments systematically identify potential risks to inform security decisions. They don't install software, manage benefits, or replace backups.
Which of the following BEST describes the purpose of a security incident response plan?
A) To provide a structured approach for handling security incidents
B) To prevent all security incidents from occurring
C) To eliminate the need for security training
D) To reduce the number of security policies
Answer: A) To provide a structured approach for handling security incidents
A security incident response plan establishes clear procedures for detecting, analyzing, containing, eradicating, and recovering from security incidents. It doesn't prevent all incidents (which is impossible), doesn't eliminate training needs, and doesn't reduce policy requirements.
Which of the following BEST describes the purpose of a security baseline?
A) To provide a standard configuration for systems to reduce vulnerabilities
B) To allow all users full access to all systems
C) To increase system performance
D) To replace the need for firewalls
Answer: A) To provide a standard configuration for systems to reduce vulnerabilities
A security baseline establishes minimum security requirements for systems, ensuring consistent configuration that reduces known vulnerabilities. It doesn't grant unlimited access, doesn't necessarily improve performance, and doesn't eliminate the need for other security controls like firewalls.
Which of the following BEST describes the purpose of a digital certificate?
A) To verify the identity of a website or user
B) To encrypt data at rest
C) To manage user accounts
D) To block spam emails
Answer: A) To verify the identity of a website or user
Digital certificates use public key infrastructure to authenticate identities. They don't encrypt data at rest, manage accounts, or block spam. </output>


1. Which of the following best describes the primary purpose of a security policy?
A) To define acceptable use of company resources
B) To enforce access control through technical means
C) To provide a framework for incident response
D) To ensure compliance with regulatory standards
Answer: A) To define acceptable use of company resources
A security policy establishes organizational standards for acceptable behavior and resource usage. While policies may influence incident response (C) and compliance (D), their primary purpose is to define acceptable use. Technical access control (B) is implemented through systems, not policies.

What is the main purpose of a vulnerability scanner?
A) To exploit identified vulnerabilities
B) To block malicious traffic in real time
C) To identify and report potential security weaknesses
D) To encrypt sensitive data at rest
Answer: C) To identify and report potential security weaknesses
Vulnerability scanners proactively scan systems to detect known vulnerabilities. They don't exploit vulnerabilities (A), block traffic (B), or encrypt data (D). Their role is detection, not remediation or prevention.
Which of the following is the most effective method to protect against credential stuffing attacks?
A) Implementing strong password policies
B) Enabling multi-factor authentication (MFA)
C) Using a password manager
D) Disabling account lockout
Answer: B) Enabling multi-factor authentication (MFA)
MFA adds additional authentication layers beyond passwords, making it extremely difficult for attackers to gain access even with valid credentials. Strong password policies (A) help but don't prevent credential reuse. Password managers (C) assist with password management but don't stop attacks. Disabling account lockout (D) increases vulnerability.
Which of the following BEST describes the purpose of a digital signature?
A) To encrypt data for confidentiality
B) To ensure data integrity and non-repudiation
C) To compress large files
D) To authenticate users via biometrics
Answer: B) To ensure data integrity and non-repudiation
Digital signatures use cryptography to verify data hasn't been altered and to prove the sender's identity. This provides integrity and non-repudiation. Encryption (A) ensures confidentiality, not integrity. Compression (C) and biometrics (D) are unrelated to digital signatures.
What is the primary purpose of a security baseline?
A) To provide a standard configuration for systems to reduce vulnerabilities
B) To allow all users full access to all systems
C) To increase system performance
D) To replace the need for firewalls
Answer: A) To provide a standard configuration for systems to reduce vulnerabilities
Security baselines establish minimum security requirements for consistent, secure configurations. They don't grant unlimited access (B), improve performance (C), or eliminate the need for other controls like firewalls (D).
Which of the following is the MOST effective way to prevent unauthorized access to a wireless network?
A) Changing the default SSID
B) Disabling SSID broadcast
C) Using WPA3 encryption
D) Setting up MAC address filtering
Answer: C) Using WPA3 encryption
WPA3 is the current standard for wireless security with robust encryption. Changing SSID (A) and disabling broadcast (B) provide minimal security through obscurity. MAC filtering (D) can be easily bypassed.
Which of the following BEST describes a zero-trust security model?
A) Trust all users inside the network perimeter
B) Verify every user and device before granting access, regardless of location
C) Allow access based on physical location only
D) Rely solely on firewalls for protection
Answer: B) Verify every user and device before granting access, regardless of location
Zero-trust assumes no implicit trust and requires continuous verification. This contrasts with trusting internal users (A), which violates zero-trust principles.
A security analyst notices that a user's account has been used to access sensitive data from an unusual geographic location. Which of the following BEST describes this type of detection?
A) Anomaly detection
B) Signature-based detection
C) Heuristic analysis
D) Behavioral analytics
Answer: A) Anomaly detection
This represents abnormal behavior deviating from normal patterns. Signature-based detection (B) looks for known patterns, heuristic analysis (C) uses rules, and behavioral analytics (D) is broader but not the most precise term.
Which of the following is a primary purpose of a business impact analysis (BIA)?
A) To identify critical systems and their recovery priorities
B) To manage employee schedules
C) To install new software
D) To replace the need for backups
Answer: A) To identify critical systems and their recovery priorities
BIA determines which systems are most critical and how quickly they must be restored. It doesn't manage schedules (B), install software (C), or replace backups (D).
Which of the following BEST describes the purpose of a risk assessment?
A) To identify threats, vulnerabilities, and potential impacts
B) To install antivirus software
C) To manage employee benefits
D) To replace the need for backups
Answer: A) To identify threats, vulnerabilities, and potential impacts
Risk assessments systematically identify potential risks to inform security decisions. They don't install software (B), manage benefits (C), or replace backups (D).
Which of the following is the BEST way to protect against cross-site scripting (XSS) attacks?
A) Using strong passwords
B) Implementing input validation and sanitization
C) Installing antivirus software
D) Disabling JavaScript in browsers
Answer: B) Implementing input validation and sanitization
This prevents malicious scripts from being executed by filtering input. Strong passwords (A) don't prevent XSS. Antivirus (C) detects malware but not XSS. Disabling JavaScript (D) breaks legitimate websites.
Which of the following BEST describes the purpose of a security patch?
A) To fix known vulnerabilities in software or systems
B) To improve system performance
C) To increase user permissions
D) To disable antivirus software
Answer: A) To fix known vulnerabilities in software or systems
Security patches address specific security flaws. They don't improve performance (B), increase permissions (C), or disable security software (D).
Which of the following BEST describes the purpose of a firewall rule that blocks all traffic by default?
A) To follow the principle of least privilege and reduce attack surface
B) To improve network speed
C) To allow all internal traffic
D) To disable logging
Answer: A) To follow the principle of least privilege and reduce attack surface
This implements least privilege by allowing only explicitly permitted traffic. It doesn't improve speed (B), allow internal traffic (C), or disable logging (D).
Which of the following BEST describes the purpose of a security incident?
A) Any event that threatens the confidentiality, integrity, or availability of information
B) A system reboot
C) A user changing their password
D) A software update
Answer: A) Any event that threatens the confidentiality, integrity, or availability of information
This is the standard definition of a security incident. Routine operations like reboots (B) and password changes (C) aren't incidents, and software updates (D) are normal maintenance.
Which of the following BEST describes the purpose of a recovery point objective (RPO)?
A) The maximum acceptable amount of data loss measured in time
B) The maximum acceptable downtime
C) The time to restore a system after failure
D) The number of backup copies
Answer: A) The maximum acceptable amount of data loss measured in time
RPO defines acceptable data loss based on time intervals. RTO (B) is maximum downtime, restoration time (C) is different, and backup count (D) is separate.
Which of the following BEST describes the purpose of a change control board (CCB)?
A) To approve or reject changes to systems to maintain stability and security
B) To manage user passwords
C) To install software updates
D) To block all network traffic
Answer: A) To approve or reject changes to systems to maintain stability and security
The CCB reviews changes to prevent unintended risks. It doesn't manage passwords (B), install updates (C), or block traffic (D).
Which of the following BEST describes the purpose of a business continuity plan (BCP)?
A) To ensure that critical systems can be restored after a disruption
B) To prevent all cyberattacks
C) To replace the need for backups
D) To manage employee salaries
Answer: A) To ensure that critical systems can be restored after a disruption
BCP outlines procedures to maintain operations during disruptions. It doesn't prevent all attacks (B), replace backups (C), or manage salaries (D).
Which of the following BEST describes the purpose of a security baseline configuration?
A) To establish minimum security requirements for systems
B) To maximize system performance
C) To disable all security features
D) To allow unlimited user access
Answer: A) To establish minimum security requirements for systems
This ensures consistent, secure configurations. It doesn't maximize performance (B), disable security (C), or allow unlimited access (D).
Which of the following BEST describes the purpose of a security policy?
A) To define acceptable behavior and security requirements
B) To manage hardware inventory
C) To increase system performance
D) To replace the need for training
Answer: A) To define acceptable behavior and security requirements
Security policies establish organizational standards. They don't manage inventory (B), increase performance (C), or replace training (D).
Which of the following BEST describes the purpose of a security awareness program?
A) To educate users about security risks and best practices
B) To install antivirus software
C) To manage employee payroll
D) To replace the need for firewalls
Answer: A) To educate users about security risks and best practices
Awareness programs train users to recognize threats. They don't install software (B), manage payroll (C), or replace firewalls (D).
Which of the following BEST describes the purpose of a security audit?
A) To evaluate compliance with security policies and identify gaps
B) To replace the need for training
C) To manage employee payroll
D) To install software updates
Answer: A) To evaluate compliance with security policies and identify gaps
Audits assess adherence to policies. They don't replace training (B), manage payroll (C), or install updates (D).
Which of the following BEST describes the purpose of a vulnerability assessment?
A) To identify and report potential security weaknesses
B) To exploit vulnerabilities in a system
C) To block all network traffic
D) To encrypt all data
Answer: A) To identify and report potential security weaknesses
This is the core purpose of vulnerability assessments. They don't exploit (B), block traffic (C), or encrypt data (D).
Which of the following BEST describes the purpose of a risk assessment?
A) To identify threats, vulnerabilities, and potential impacts
B) To install antivirus software
C) To manage employee benefits
D) To replace the need for backups
Answer: A) To identify threats, vulnerabilities, and potential impacts
This is the fundamental purpose of risk assessments. They don't install software (B), manage benefits (C), or replace backups (D).
Which of the following BEST describes the purpose of a security incident response plan?
A) To provide a structured approach for handling security incidents
B) To prevent all security incidents from occurring
C) To eliminate the need for security training
D) To reduce the number of security policies
Answer: A) To provide a structured approach for handling security incidents
This is the primary purpose of an incident response plan. It doesn't prevent all incidents (B), eliminate training (C), or reduce policies (D).
Which of the following BEST describes the purpose of a security baseline?
A) To provide a standard configuration for systems to reduce vulnerabilities
B) To allow all users full access to all systems
C) To increase system performance
D) To replace the need for firewalls
Answer: A) To provide a standard configuration for systems to reduce vulnerabilities
This is the primary purpose of security baselines. They don't grant unlimited access (B), improve performance (C), or eliminate firewall needs (D).
Which of the following BEST describes the purpose of a digital certificate?
A) To verify the identity of a website or user
B) To encrypt data at rest
C) To manage user accounts
D) To block spam emails
Answer: A) To verify the identity of a website or user
Digital certificates authenticate identities through public key infrastructure. They don't encrypt data at rest (B), manage accounts (C), or block spam (D).
Which of the following BEST describes the purpose of a security patch?
A) To fix known vulnerabilities in software or systems
B) To improve system performance
C) To increase user permissions
D) To disable antivirus software
Answer: A) To fix known vulnerabilities in software or systems
This is the primary purpose of security patches. They don't improve performance (B), increase permissions (C), or disable security software (D).
Which of the following BEST describes the purpose of a firewall rule that blocks all traffic by default?
A) To follow the principle of least privilege and reduce attack surface
B) To improve network speed
C) To allow all internal traffic
D) To disable logging
Answer: A) To follow the principle of least privilege and reduce attack surface
This implements least privilege by allowing only explicitly permitted traffic. It doesn't improve speed (B), allow internal traffic (C), or disable logging (D).
Which of the following BEST describes the purpose of a security incident?
A) Any event that threatens the confidentiality, integrity, or availability of information
B) A system reboot
C) A user changing their password
D) A software update
Answer: A) Any event that threatens the confidentiality, integrity, or availability of information
This is the standard definition of a security incident. Routine operations like reboots (B) and password changes (C) aren't incidents, and software updates (D) are normal maintenance.
Which of the following BEST describes the purpose of a recovery point objective (RPO)?
A) The maximum acceptable amount of data loss measured in time
B) The maximum acceptable downtime
C) The time to restore a system after failure
D) The number of backup copies
Answer: A) The maximum acceptable amount of data loss measured in time
RPO defines acceptable data loss based on time intervals. RTO (B) is maximum downtime, restoration time (C) is different, and backup count (D) is separate.
Which of the following BEST describes the purpose of a change control board (CCB)?
A) To approve or reject changes to systems to maintain stability and security
B) To manage user passwords
C) To install software updates
D) To block all network traffic
Answer: A) To approve or reject changes to systems to maintain stability and security
The CCB reviews changes to prevent unintended risks. It doesn't manage passwords (B), install updates (C), or block traffic (D).
Which of the following BEST describes the purpose of a business continuity plan (BCP)?
A) To ensure that critical systems can be restored after a disruption
B) To prevent all cyberattacks
C) To replace the need for backups
D) To manage employee salaries
Answer: A) To ensure that critical systems can be restored after a disruption
BCP outlines procedures to maintain operations during disruptions. It doesn't prevent all attacks (B), replace backups (C), or manage salaries (D).
Which of the following BEST describes the purpose of a security baseline configuration?
A) To establish minimum security requirements for systems
B) To maximize system performance
C) To disable all security features
D) To allow unlimited user access
Answer: A) To establish minimum security requirements for systems
This ensures consistent, secure configurations. It doesn't maximize performance (B), disable security (C), or allow unlimited access (D).
Which of the following BEST describes the purpose of a security policy?
A) To define acceptable behavior and security requirements
B) To manage hardware inventory
C) To increase system performance
D) To replace the need for training
Answer: A) To define acceptable behavior and security requirements
Security policies establish organizational standards. They don't manage inventory (B), increase performance (C), or replace training (D).
Which of the following BEST describes the purpose of a security awareness program?
A) To educate users about security risks and best practices
B) To install antivirus software
C) To manage employee payroll
D) To replace the need for firewalls
Answer: A) To educate users about security risks and best practices
Awareness programs train users to recognize threats. They don't install software (B), manage payroll (C), or replace firewalls (D).
Which of the following BEST describes the purpose of a security audit?
A) To evaluate compliance with security policies and identify gaps
B) To replace the need for training
C) To manage employee payroll
D) To install software updates
Answer: A) To evaluate compliance with security policies and identify gaps
Audits assess adherence to policies. They don't replace training (B), manage payroll (C), or install updates (D).
Which of the following BEST describes the purpose of a vulnerability assessment?
A) To identify and report potential security weaknesses
B) To exploit vulnerabilities in a system
C) To block all network traffic
D) To encrypt all data
Answer: A) To identify and report potential security weaknesses
This is the core purpose of vulnerability assessments. They don't exploit (B), block traffic (C), or encrypt data (D).
Which of the following BEST describes the purpose of a risk assessment?
A) To identify threats, vulnerabilities, and potential impacts
B) To install antivirus software
C) To manage employee benefits
D) To replace the need for backups
Answer: A) To identify threats, vulnerabilities, and potential impacts
This is the fundamental purpose of risk assessments. They don't install software (B), manage benefits (C), or replace backups (D).
Which of the following BEST describes the purpose of a security incident response plan?
A) To provide a structured approach for handling security incidents
B) To prevent all security incidents from occurring
C) To eliminate the need for security training
D) To reduce the number of security policies
Answer: A) To provide a structured approach for handling security incidents
This is the primary purpose of an incident response plan. It doesn't prevent all incidents (B), eliminate training (C), or reduce policies (D).
Which of the following BEST describes the purpose of a security baseline?
A) To provide a standard configuration for systems to reduce vulnerabilities
B) To allow all users full access to all systems
C) To increase system performance
D) To replace the need for firewalls
Answer: A) To provide a standard configuration for systems to reduce vulnerabilities
This is the primary purpose of security baselines. They don't grant unlimited access (B), improve performance (C), or eliminate firewall needs (D).
Which of the following BEST describes the purpose of a digital certificate?
A) To verify the identity of a website or user
B) To encrypt data at rest
C) To manage user accounts
D) To block spam emails
Answer: A) To verify the identity of a website or user
Digital certificates authenticate identities through public key infrastructure. They don't encrypt data at rest (B), manage accounts (C), or block spam (D).
Which of the following BEST describes the purpose of a security patch?
A) To fix known vulnerabilities in software or systems
B) To improve system performance
C) To increase user permissions
D) To disable antivirus software
Answer: A) To fix known vulnerabilities in software or systems
This is the primary purpose of security patches. They don't improve performance (B), increase permissions (C), or disable security software (D).
Which of the following BEST describes the purpose of a firewall rule that blocks all traffic by default?
A) To follow the principle of least privilege and reduce attack surface
B) To improve network speed
C) To allow all internal traffic
D) To disable logging
Answer: A) To follow the principle of least privilege and reduce attack surface
This implements least privilege by allowing only explicitly permitted traffic. It doesn't improve speed (B), allow internal traffic (C), or disable logging (D).
Which of the following BEST describes the purpose of a security incident?
A) Any event that threatens the confidentiality, integrity, or availability of information
B) A system reboot
C) A user changing their password
D) A software update
Answer: A) Any event that threatens the confidentiality, integrity, or availability of information
This is the standard definition of a security incident. Routine operations like reboots (B) and password changes (C) aren't incidents, and software updates (D) are normal maintenance.
Which of the following BEST describes the purpose of a recovery point objective (RPO)?
A) The maximum acceptable amount of data loss measured in time
B) The maximum acceptable downtime
C) The time to restore a system after failure
D) The number of backup copies
Answer: A) The maximum acceptable amount of data loss measured in time
RPO defines acceptable data loss based on time intervals. RTO (B) is maximum downtime, restoration time (C) is different, and backup count (D) is separate.
Which of the following BEST describes the purpose of a change control board (CCB)?
A) To approve or reject changes to systems to maintain stability and security
B) To manage user passwords
C) To install software updates
D) To block all network traffic
Answer: A) To approve or reject changes to systems to maintain stability and security
The CCB reviews changes to prevent unintended risks. It doesn't manage passwords (B), install updates (C), or block traffic (D).
Which of the following BEST describes the purpose of a business continuity plan (BCP)?
A) To ensure that critical systems can be restored after a disruption
B) To prevent all cyberattacks
C) To replace the need for backups
D) To manage employee salaries
Answer: A) To ensure that critical systems can be restored after a disruption
BCP outlines procedures to maintain operations during disruptions. It doesn't prevent all attacks (B), replace backups (C), or manage salaries (D).
Which of the following BEST describes the purpose of a security baseline configuration?
A) To establish minimum security requirements for systems
B) To maximize system performance
C) To disable all security features
D) To allow unlimited user access
Answer: A) To establish minimum security requirements for systems
This ensures consistent, secure configurations. It doesn't maximize performance (B), disable security (C), or allow unlimited access (D).
Which of the following BEST describes the purpose of a security policy?
A) To define acceptable behavior and security requirements
B) To manage hardware inventory
C) To increase system performance
D) To replace the need for training
Answer: A) To define acceptable behavior and security requirements
Security policies establish organizational standards. They don't manage inventory (B), increase performance (C), or replace training (D).
Which of the following BEST describes the purpose of a security awareness program?
A) To educate users about security risks and best practices
B) To install antivirus software
C) To manage employee payroll
D) To replace the need for firewalls
Answer: A) To educate users about security risks and best practices
Awareness programs train users to recognize threats. They don't install software (B), manage payroll (C), or replace firewalls (D).
Which of the following BEST describes the purpose of a security incident response plan?
A) To provide a structured approach for handling security incidents
B) To prevent all security incidents from occurring
C) To eliminate the need for security training
D) To reduce the number of security policies
Answer: A) To provide a structured approach for handling security incidents
This is the primary purpose of an incident response plan. It doesn't prevent all incidents (B), eliminate training (C), or reduce policies (D).
Which of the following BEST describes the purpose of a security baseline?
A) To provide a standard configuration for systems to reduce vulnerabilities
B) To allow all users full access to all systems
C) To increase system performance
D) To replace the need for firewalls
Answer: A) To provide a standard configuration for systems to reduce vulnerabilities
This is the primary purpose of security baselines. They don't grant unlimited access (B), improve performance (C), or eliminate firewall needs (D).
Which of the following BEST describes the purpose of a digital certificate?
A) To verify the identity of a website or user
B) To encrypt data at rest
C) To manage user accounts
D) To block spam emails
Answer: A) To verify the identity of a website or user
Digital certificates authenticate identities through public key infrastructure. They don't encrypt data at rest (B), manage accounts (C), or block spam (D).
Which of the following BEST describes the purpose of a security patch?
A) To fix known vulnerabilities in software or systems
B) To improve system performance
C) To increase user permissions
D) To disable antivirus software
Answer: A) To fix known vulnerabilities in software or systems
This is the primary purpose of security patches. They don't improve performance (B), increase permissions (C), or disable security software (D).
Which of the following BEST describes the purpose of a firewall rule that blocks all traffic by default?
A) To follow the principle of least privilege and reduce attack surface
B) To improve network speed
C) To allow all internal traffic
D) To disable logging
Answer: A) To follow the principle of least privilege and reduce attack surface
This implements least privilege by allowing only explicitly permitted traffic. It doesn't improve speed (B), allow internal traffic (C), or disable logging (D).
Which of the following BEST describes the purpose of a security incident?
A) Any event that threatens the confidentiality, integrity, or availability of information
B) A system reboot
C) A user changing their password
D) A software update
Answer: A) Any event that threatens the confidentiality, integrity, or availability of information
This is the standard definition of a security incident. Routine operations like reboots (B) and password changes (C) aren't incidents, and software updates (D) are normal maintenance.
Which of the following BEST describes the purpose of a recovery point objective (RPO)?
A) The maximum acceptable amount of data loss measured in time
B) The maximum acceptable downtime
C) The time to restore a system after failure
D) The number of backup copies
Answer: A) The maximum acceptable amount of data loss measured in time
RPO defines acceptable data loss based on time intervals. RTO (B) is maximum downtime, restoration time (C) is different, and backup count (D) is separate.
Which of the following BEST describes the purpose of a change control board (CCB)?
A) To approve or reject changes to systems to maintain stability and security
B) To manage user passwords
C) To install software updates
D) To block all network traffic
Answer: A) To approve or reject changes to systems to maintain stability and security
The CCB reviews changes to prevent unintended risks. It doesn't manage passwords (B), install updates (C), or block traffic (D).
Which of the following BEST describes the purpose of a business continuity plan (BCP)?
A) To ensure that critical systems can be restored after a disruption
B) To prevent all cyberattacks
C) To replace the need for backups
D) To manage employee salaries
Answer: A) To ensure that critical systems can be restored after a disruption
BCP outlines procedures to maintain operations during disruptions. It doesn't prevent all attacks (B), replace backups (C), or manage salaries (D).
Which of the following BEST describes the purpose of a security baseline configuration?
A) To establish minimum security requirements for systems
B) To maximize system performance
C) To disable all security features
D) To allow unlimited user access
Answer: A) To establish minimum security requirements for systems
This ensures consistent, secure configurations. It doesn't maximize performance (B), disable security (C), or allow unlimited access (D).
Which of the following BEST describes the purpose of a security policy?
A) To define acceptable behavior and security requirements
B) To manage hardware inventory
C) To increase system performance
D) To replace the need for training
Answer: A) To define acceptable behavior and security requirements
Security policies establish organizational standards. They don't manage inventory (B), increase performance (C), or replace training (D).
Which of the following BEST describes the purpose of a security awareness program?
A) To educate users about security risks and best practices
B) To install antivirus software
C) To manage employee payroll
D) To replace the need for firewalls
Answer: A) To educate users about security risks and best practices
Awareness programs train users to recognize threats. They don't install software (B), manage payroll (C), or replace firewalls (D).
Which of the following BEST describes the purpose of a security audit?
A) To evaluate compliance with security policies and identify gaps
B) To replace the need for training
C) To manage employee payroll
D) To install software updates
Answer: A) To evaluate compliance with security policies and identify gaps
Audits assess adherence to policies. They don't replace training (B), manage payroll (C), or install updates (D).
Which of the following BEST describes the purpose of a vulnerability assessment?
A) To identify and report potential security weaknesses
B) To exploit vulnerabilities in a system
C) To block all network traffic
D) To encrypt all data
Answer: A) To identify and report potential security weaknesses
This is the core purpose of vulnerability assessments. They don't exploit (B), block traffic (C), or encrypt data (D).
Which of the following BEST describes the purpose of a risk assessment?
A) To identify threats, vulnerabilities, and potential impacts
B) To install antivirus software
C) To manage employee benefits
D) To replace the need for backups
Answer: A) To identify threats, vulnerabilities, and potential impacts
This is the fundamental purpose of risk assessments. They don't install software (B), manage benefits (C), or replace backups (D).
Which of the following BEST describes the purpose of a security incident response plan?
A) To provide a structured approach for handling security incidents
B) To prevent all security incidents from occurring
C) To eliminate the need for security training
D) To reduce the number of security policies
Answer: A) To provide a structured approach for handling security incidents
This is the primary purpose of an incident response plan. It doesn't prevent all incidents (B), eliminate training (C), or reduce policies (D).
Which of the following BEST describes the purpose of a security baseline?
A) To provide a standard configuration for systems to reduce vulnerabilities
B) To allow all users full access to all systems
C) To increase system performance
D) To replace the need for firewalls
Answer: A) To provide a standard configuration for systems to reduce vulnerabilities
This is the primary purpose of security baselines. They don't grant unlimited access (B), improve performance (C), or eliminate firewall needs (D).
Which of the following BEST describes the purpose of a digital certificate?
A) To verify the identity of a website or user
B) To encrypt data at rest
C) To manage user accounts
D) To block spam emails
Answer: A) To verify the identity of a website or user
Digital certificates authenticate identities through public key infrastructure. They don't encrypt data at rest (B), manage accounts (C), or block spam (D).
Which of the following BEST describes the purpose of a security patch?
A) To fix known vulnerabilities in software or systems
B) To improve system performance
C) To increase user permissions
D) To disable antivirus software
Answer: A) To fix known vulnerabilities in software or systems
This is the primary purpose of security patches. They don't improve performance (B), increase permissions (C), or disable security software (D).
Which of the following BEST describes the purpose of a firewall rule that blocks all traffic by default?
A) To follow the principle of least privilege and reduce attack surface
B) To improve network speed
C) To allow all internal traffic
D) To disable logging
Answer: A) To follow the principle of least privilege and reduce attack surface
This implements least privilege by allowing only explicitly permitted traffic. It doesn't improve speed (B), allow internal traffic (C), or disable logging (D).
Which of the following BEST describes the purpose of a security incident?
A) Any event that threatens the confidentiality, integrity, or availability of information
B) A system reboot
C) A user changing their password
D) A software update
Answer: A) Any event that threatens the confidentiality, integrity, or availability of information
This is the standard definition of a security incident. Routine operations like reboots (B) and password changes (C) aren't incidents, and software updates (D) are normal maintenance.
Which of the following BEST describes the purpose of a recovery point objective (RPO)?
A) The maximum acceptable amount of data loss measured in time
B) The maximum acceptable downtime
C) The time to restore a system after failure
D) The number of backup copies
Answer: A) The maximum acceptable amount of data loss measured in time
RPO defines acceptable data loss based on time intervals. RTO (B) is maximum downtime, restoration time (C) is different, and backup count (D) is separate.
Which of the following BEST describes the purpose of a change control board (CCB)?
A) To approve or reject changes to systems to maintain stability and security
B) To manage user passwords
C) To install software updates
D) To block all network traffic
Answer: A) To approve or reject changes to systems to maintain stability and security
The CCB reviews changes to prevent unintended risks. It doesn't manage passwords (B), install updates (C), or block traffic (D).
Which of the following BEST describes the purpose of a business continuity plan (BCP)?
A) To ensure that critical systems can be restored after a disruption
B) To prevent all cyberattacks
C) To replace the need for backups
D) To manage employee salaries
Answer: A) To ensure that critical systems can be restored after a disruption
BCP outlines procedures to maintain operations during disruptions. It doesn't prevent all attacks (B), replace backups (C), or manage salaries (D).
Which of the following BEST describes the purpose of a security baseline configuration?
A) To establish minimum security requirements for systems
B) To maximize system performance
C) To disable all security features
D) To allow unlimited user access
Answer: A) To establish minimum security requirements for systems
This ensures consistent, secure configurations. It doesn't maximize performance (B), disable security (C), or allow unlimited access (D).
Which of the following BEST describes the purpose of a security policy?
A) To define acceptable behavior and security requirements
B) To manage hardware inventory
C) To increase system performance
D) To replace the need for training
Answer: A) To define acceptable behavior and security requirements
Security policies establish organizational standards. They don't manage inventory (B), increase performance (C), or replace training (D).
Which of the following BEST describes the purpose of a security awareness program?
A) To educate users about security risks and best practices
B) To install antivirus software
C) To manage employee payroll
D) To replace the need for firewalls
Answer: A) To educate users about security risks and best practices
Awareness programs train users to recognize threats. They don't install software (B), manage payroll (C), or replace firewalls (D).
Which of the following BEST describes the purpose of a security audit?
A) To evaluate compliance with security policies and identify gaps
B) To replace the need for training
C) To manage employee payroll
D) To install software updates
Answer: A) To evaluate compliance with security policies and identify gaps
Audits assess adherence to policies. They don't replace training (B), manage payroll (C), or install updates (D).
Which of the following BEST describes the purpose of a vulnerability assessment?
A) To identify and report potential security weaknesses
B) To exploit vulnerabilities in a system
C) To block all network traffic
D) To encrypt all data
Answer: A) To identify and report potential security weaknesses
This is the core purpose of vulnerability assessments. They don't exploit (B), block traffic (C), or encrypt data (D).
Which of the following BEST describes the purpose of a risk assessment?
A) To identify threats, vulnerabilities, and potential impacts
B) To install antivirus software
C) To manage employee benefits
D) To replace the need for backups
Answer: A) To identify threats, vulnerabilities, and potential impacts
This is the fundamental purpose of risk assessments. They don't install software (B), manage benefits (C), or replace backups (D).
Which of the following BEST describes the purpose of a security incident response plan?
A) To provide a structured approach for handling security incidents
B) To prevent all security incidents from occurring
C) To eliminate the need for security training
D) To reduce the number of security policies
Answer: A) To provide a structured approach for handling security incidents
This is the primary purpose of an incident response plan. It doesn't prevent all incidents (B), eliminate training (C), or reduce policies (D).
Which of the following BEST describes the purpose of a security baseline?
A) To provide a standard configuration for systems to reduce vulnerabilities
B) To allow all users full access to all systems
C) To increase system performance
D) To replace the need for firewalls
Answer: A) To provide a standard configuration for systems to reduce vulnerabilities
This is the primary purpose of security baselines. They don't grant unlimited access (B), improve performance (C), or eliminate firewall needs (D).
Which of the following BEST describes the purpose of a digital certificate?
A) To verify the identity of a website or user
B) To encrypt data at rest
C) To manage user accounts
D) To block spam emails
Answer: A) To verify the identity of a website or user
Digital certificates authenticate identities through public key infrastructure. They don't encrypt data at rest (B), manage accounts (C), or block spam (D).
Which of the following BEST describes the purpose of a security patch?
A) To fix known vulnerabilities in software or systems
B) To improve system performance
C) To increase user permissions
D) To disable antivirus software
Answer: A) To fix known vulnerabilities in software or systems
This is the primary purpose of security patches. They don't improve performance (B), increase permissions (C), or disable security software (D).
Which of the following BEST describes the purpose of a firewall rule that blocks all traffic by default?
A) To follow the principle of least privilege and reduce attack surface
B) To improve network speed
C) To allow all internal traffic
D) To disable logging
Answer: A) To follow the principle of least privilege and reduce attack surface
This implements least privilege by allowing only explicitly permitted traffic. It doesn't improve speed (B), allow internal traffic (C), or disable logging (D).
Which of the following BEST describes the purpose of a security incident?
A) Any event that threatens the confidentiality, integrity, or availability of information
B) A system reboot
C) A user changing their password
D) A software update
Answer: A) Any event that threatens the confidentiality, integrity, or availability of information
This is the standard definition of a security incident. Routine operations like reboots (B) and password changes (C) aren't incidents, and software updates (D) are normal maintenance.
Which of the following BEST describes the purpose of a recovery point objective (RPO)?
A) The maximum acceptable amount of data loss measured in time
B) The maximum acceptable downtime
C) The time to restore a system after failure
D) The number of backup copies
Answer: A) The maximum acceptable amount of data loss measured in time
RPO defines acceptable data loss based on time intervals. RTO (B) is maximum downtime, restoration time (C) is different, and backup count (D) is separate.
Which of the following BEST describes the purpose of a change control board (CCB)?
A) To approve or reject changes to systems to maintain stability and security
B) To manage user passwords
C) To install software updates
D) To block all network traffic
Answer: A) To approve or reject changes to systems to maintain stability and security
The CCB reviews changes to prevent unintended risks. It doesn't manage passwords (B), install updates (C), or block traffic (D).
Which of the following BEST describes the purpose of a business continuity plan (BCP)?
A) To ensure that critical systems can be restored after a disruption
B) To prevent all cyberattacks
C) To replace the need for backups
D) To manage employee salaries
Answer: A) To ensure that critical systems can be restored after a disruption
BCP outlines procedures to maintain operations during disruptions. It doesn't prevent all attacks (B), replace backups (C), or manage salaries (D).
Which of the following BEST describes the purpose of a security baseline configuration?
A) To establish minimum security requirements for systems
B) To maximize system performance
C) To disable all security features
D) To allow unlimited user access
Answer: A) To establish minimum security requirements for systems
This ensures consistent, secure configurations. It doesn't maximize performance (B), disable security (C), or allow unlimited access (D).
Which of the following BEST describes the purpose of a security policy?
A) To define acceptable behavior and security requirements
B) To manage hardware inventory
C) To increase system performance
D) To replace the need for training
Answer: A) To define acceptable behavior and security requirements
Security policies establish organizational standards. They don't manage inventory (B), increase performance (C), or replace training (D).
Which of the following BEST describes the purpose of a security awareness program?
A) To educate users about security risks and best practices
B) To install antivirus software
C) To manage employee payroll
D) To replace the need for firewalls
Answer: A) To educate users about security risks and best practices
Awareness programs train users to recognize threats. They don't install software (B), manage payroll (C), or replace firewalls (D).
Which of the following BEST describes the purpose of a security audit?
A) To evaluate compliance with security policies and identify gaps
B) To replace the need for training
C) To manage employee payroll
D) To install software updates
Answer: A) To evaluate compliance with security policies and identify gaps
Audits assess adherence to policies. They don't replace training (B), manage payroll (C), or install updates (D).
Which of the following BEST describes the purpose of a vulnerability assessment?
A) To identify and report potential security weaknesses
B) To exploit vulnerabilities in a system
C) To block all network traffic
D) To encrypt all data
Answer: A) To identify and report potential security weaknesses
This is the core purpose of vulnerability assessments. They don't exploit (B), block traffic (C), or encrypt data (D).
Which of the following BEST describes the purpose of a risk assessment?
A) To identify threats, vulnerabilities, and potential impacts
B) To install antivirus software
C) To manage employee benefits
D) To replace the need for backups
Answer: A) To identify threats, vulnerabilities, and potential impacts
This is the fundamental purpose of risk assessments. They don't install software (B), manage benefits (C), or replace backups (D).
Which of the following BEST describes the purpose of a security incident response plan?
A) To provide a structured approach for handling security incidents
B) To prevent all security incidents from occurring
C) To eliminate the need for security training
D) To reduce the number of security policies
Answer: A) To provide a structured approach for handling security incidents
This is the primary purpose of an incident response plan. It doesn't prevent all incidents (B), eliminate training (C), or reduce policies (D).
Which of the following BEST describes the purpose of a security baseline?
A) To provide a standard configuration for systems to reduce vulnerabilities
B) To allow all users full access to all systems
C) To increase system performance
D) To replace the need for firewalls
Answer: A) To provide a standard configuration for systems to reduce vulnerabilities
This is the primary purpose of security baselines. They don't grant unlimited access (B), improve performance (C), or eliminate firewall needs (D).
Which of the following BEST describes the purpose of a digital certificate?
A) To verify the identity of a website or user
B) To encrypt data at rest
C) To manage user accounts
D) To block spam emails
Answer: A) To verify the identity of a website or user
Digital certificates authenticate identities through public key infrastructure. They don't encrypt data at rest (B), manage accounts (C), or block spam (D).
Which of the following BEST describes the purpose of a security patch?
A) To fix known vulnerabilities in software or systems
B) To improve system performance
C) To increase user permissions
D) To disable antivirus software
Answer: A) To fix known vulnerabilities in software or systems
This is the primary purpose of security patches. They don't improve performance (B), increase permissions (C), or disable security software (D).
Which of the following BEST describes the purpose of a firewall rule that blocks all traffic by default?
A) To follow the principle of least privilege and reduce attack surface
B) To improve network speed
C) To allow all internal traffic
D) To disable logging
Answer: A) To follow the principle of least privilege and reduce attack surface
This implements least privilege by allowing only explicitly permitted traffic. It doesn't improve speed (B), allow internal traffic (C), or disable logging (D). </output>