#!/bin/bash

# Enhanced Linux Hardening and Administration Script for Ubuntu LTS

# Function to log actions
log_action() {
    echo "$(date) - $1" >> /var/log/ubuntu_hardening.log
}

# Ensure the script is run as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   log_action "Attempted to run script without root privileges"
   exit 1
fi

# Update and Upgrade the System
echo "Updating and Upgrading the System..."
if apt-get update && apt-get upgrade -y && apt-get dist-upgrade -y && apt-get autoremove -y; then
   log_action "System updated and upgraded"
else
   log_action "Failed to update and upgrade system"
   exit 1
fi

# Install Essential Security Packages
echo "Installing essential security packages..."
if apt-get install -y unattended-upgrades fail2ban ufw; then
   log_action "Installed essential security packages"
else
   log_action "Failed to install essential security packages"
   exit 1
fi

# Enable and Configure Firewall
echo "Configuring UFW (Uncomplicated Firewall)..."
if ufw enable && ufw default deny incoming && ufw default allow outgoing && ufw logging on; then
   log_action "Configured UFW"
else
   log_action "Failed to configure UFW"
   exit 1
fi
# Add additional rules as needed, e.g., ufw allow ssh

# Configure Automatic Security Updates
echo "Configuring automatic security updates..."
cat > /etc/apt/apt.conf.d/20auto-upgrades << EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF
log_action "Configured automatic security updates"

# Function to manage sudo group members
manage_sudo_users() {
    echo "Auditing sudo group members..."
    log_action "Auditing sudo group members"
    local users=$(getent group sudo | cut -d: -f4)
    local user_array=(${users//,/ })
    
    for user in "${user_array[@]}"; do
        echo "Do you want to keep $user in the sudo group? [y/N]"
        read -r response
        if [[ "$response" =~ ^([nN][oO]|[nN])$ ]]; then
            if deluser "$user" sudo; then
               echo "$user removed from sudo group."
               log_action "$user removed from sudo group"
            else
               echo "Failed to remove $user from sudo group."
               log_action "Failed to remove $user from sudo group"
            fi
         else
            echo "$user kept in sudo group."
            log_action "$user kept in sudo group"
        fi
    done
}

# Function to check and modify sudoers file
check_and_modify_sudoers() {
    echo "Verifying and modifying /etc/sudoers and /etc/sudoers.d..."
    log_action "Checking /etc/sudoers and /etc/sudoers.d"

    # Backup sudoers file
   cp /etc/sudoers /etc/sudoers.backup

    # Check and modify /etc/sudoers
   if grep -Eqs 'NOPASSWD|!authenticate' /etc/sudoers; then
        echo "Found 'NOPASSWD' or '!authenticate' in /etc/sudoers. Removing..."
        log_action "Found insecure entries in /etc/sudoers. Modifying..."
        sed -i '/NOPASSWD/d' /etc/sudoers
        sed -i '/!authenticate/d' /etc/sudoers
   else
		echo "No insecure entries found in /etc/sudoers."
  		log_action "No insecure entries in etc/sudoers"
   fi

    # Check and modify files in /etc/sudoers.d
    for file in /etc/sudoers.d/*; do
        if grep -Eqs 'NOPASSWD|!authenticate' "$file"; then
            echo "Found 'NOPASSWD' or '!authenticate' in $file. Removing..."
				log_action "Found insecure entries in /etc/sudoers.d. Modifying..."
            sed -i '/NOPASSWD/d' "$file"
            sed -i '/!authenticate/d' "$file"
			else
				echo "No insecure entries found in /etc/sudoers.d"
	    		log_action "No insecure entries in /etc/sudoers.d"
		 	fi
	 done
}

# Function to set default umask for all users
set_default_umask() {
    echo "Checking and setting default umask for all users..."

    local current_umask=$(grep "^UMASK" /etc/login.defs | awk '{print $2}')

    if [ "$current_umask" != "077" ]; then
        echo "Setting umask to 077 in /etc/login.defs..."
        sed -i '/^UMASK/ s/[0-9]\{3\}/077/' /etc/login.defs
    else
        echo "Default umask is already set to 077."
    fi
}

# Function to set automatic session termination after inactivity
set_auto_logout() {
    echo "Setting automatic logout for all users after 10 minutes of inactivity..."

    # Checking and setting TMOUT in /etc/profile
    if ! grep -q "TMOUT=" /etc/profile; then
        echo "TMOUT=600" >> /etc/profile
        echo "export TMOUT" >> /etc/profile
    else
        sed -i '/TMOUT=/c\TMOUT=600' /etc/profile
    fi
}

# Function to install vlock if it is not installed
install_vlock() {
    echo "Checking for the vlock package..."

    if ! dpkg -s vlock &>/dev/null; then
        echo "vlock package is not installed. Installing..."
        apt-get update
        apt-get install -y vlock
    else
        echo "vlock package is already installed."
    fi
}

# Harden SSH Access
harden_ssh() {
    echo "Hardening SSH..."
    # Modify default port, disable root login, and set MaxAuthTries
    sed -i 's/#Port 22/Port 2222/' /etc/ssh/sshd_config
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/#MaxAuthTries 6/MaxAuthTries 3/' /etc/ssh/sshd_config

    # Disallow unattended or automatic login
    echo "Disallowing unattended or automatic login for SSH..."
    sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/' /etc/ssh/sshd_config
    sed -i 's/#PermitUserEnvironment no/PermitUserEnvironment no/' /etc/ssh/sshd_config

    systemctl restart sshd
}

# Disable Unused Network Services
echo "Disabling unused network services..."
# Function to check and remove a service
remove_service() {
    local service_name=$1
    echo "Checking for $service_name service..."
    if systemctl is-enabled --quiet "$service_name"; then
        echo "Disabling and removing $service_name..."
        systemctl stop "$service_name"
        systemctl disable "$service_name"
        apt-get remove --purge -y "$service_name"
    else
        echo "$service_name is not enabled or installed."
    fi
}

# Function to replace FTP with SFTP or FTPS
replace_ftp() {
    echo "Checking for FTP service..."
    if systemctl is-enabled --quiet "vsftpd"; then
        echo "Removing FTP service..."
        systemctl stop "vsftpd"
        systemctl disable "vsftpd"
        apt-get remove --purge -y "vsftpd"
        echo "FTP service removed. Consider configuring SFTP or FTPS as a secure alternative."
    else
        echo "FTP service is not enabled or installed."
    fi
}

# Check for Insecure Services
remove_service "rsh-server"
remove_service "telnetd"
remove_service "apache2"
remove_service "nginx"
remove_service "lighttpd"
remove_service "nis"
remove_service "sendmail"
remove_service "postfix"
replace_ftp

# User Management: Example - Disable guest account
echo "Disabling guest account..."
sh -c 'printf "[Seat:*]\nallow-guest=false\n" >/etc/lightdm/lightdm.conf.d/50-no-guest.conf'

configure_audit_rules() {
    echo "Configuring audit system for monitoring the use of sensitive commands..."

    # Check if auditd is installed
    if ! dpkg -s auditd &>/dev/null; then
        echo "auditd package is not installed. Installing..."
        apt-get update
        apt-get install -y auditd
    fi
    
    # Function to add an audit rule if not already present
    add_audit_rule() {
        local rule="$1"
        if ! grep -Fxq "$rule" /etc/audit/rules.d/audit.rules; then
            echo "$rule" >> /etc/audit/rules.d/audit.rules
        fi
    }

    # Audit rules for specified files and commands
    add_audit_rule "-w /var/log/tallylog -p wa -k audit_tallylog"
    add_audit_rule "-w /var/log/faillog -p wa -k audit_faillog"
    add_audit_rule "-w /usr/bin/newgrp -p x -k audit_newgrp"
    add_audit_rule "-w /usr/bin/chcon -p x -k audit_chcon"
    add_audit_rule "-w /usr/bin/setfacl -p x -k audit_setfacl"
    add_audit_rule "-w /usr/bin/passwd -p x -k audit_passwd"
    add_audit_rule "-w /usr/sbin/unix_update -p x -k audit_unix_update"
    add_audit_rule "-a always,exit -F arch=b64 -S delete_module -k audit_delete_module"
    add_audit_rule "-a always,exit -F arch=b64 -S init_module,finit_module -k audit_module_management"
    add_audit_rule "-w /usr/sbin/pam_timestamp_check -p x -k audit_pam_timestamp"
    add_audit_rule "-w /usr/bin/crontab -p x -k audit_crontab"
    add_audit_rule "-w /usr/sbin/usermod -p x -k audit_usermod"
    add_audit_rule "-w /usr/sbin/change -p x -k audit_change"
    add_audit_rule "-w /usr/bin/gpasswd -p x -k audit_gpasswd"
    # Add other rules here as needed

    # Restart auditd to apply changes
    systemctl restart auditd
    echo "Audit rules configured."
}

# Function to prevent direct root login
prevent_direct_root_login() {
    echo "Ensuring direct root login is disabled..."

    # Disable direct root SSH login
    if grep -q "^PermitRootLogin" /etc/ssh/sshd_config; then
        sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    else
        echo "PermitRootLogin no" >> /etc/ssh/sshd_config
    fi

    # Disable root password
    passwd -l root

    systemctl restart sshd
    echo "Direct root login has been disabled."
}

# Require Authentication on Single-User Mode
echo "Configuring GRUB to require authentication for single-user mode..."
echo 'GRUB_DISABLE_RECOVERY="true"' >> /etc/default/grub

# Set GRUB password
echo "Setting up GRUB password..."
echo "Please enter the password for GRUB:"
read -s GRUB_PASS
GRUB_HASH=$(echo -e "$GRUB_PASS\n$GRUB_PASS" | grub-mkpasswd-pbkdf2 | awk '/PBKDF2 hash of your password is/{print $NF}')
echo "set superusers=\"root\"" >> /etc/grub.d/40_custom
echo "password_pbkdf2 root $GRUB_HASH" >> /etc/grub.d/40_custom
update-grub

# Secure PAM Configuration
secure_pam() {
    echo "Securing PAM..."

    # Ensure password complexity and strength
    apt-get install libpam-pwquality -y
    sed -i '/pam_pwquality.so/ s/^#//' /etc/pam.d/common-password
    sed -i '/pam_pwquality.so/ s/retry=3/minlen=12 retry=3 difok=3/' /etc/pam.d/common-password

    # Other PAM security measures can be added here
}

# Check for Blank or Null Passwords
check_blank_passwords() {
    echo "Checking for blank or null passwords..."
    local users_with_blank_passwords=$(awk -F: '($2 == "" || $2 == "!") { print $1 }' /etc/shadow)

    for user in $users_with_blank_passwords; do
        echo "User '$user' has a blank or null password."
        echo "Choose an action for this account: [C]hange password, [L]ock account, [I]gnore?"
        read -r action
        case "$action" in
            [Cc]* )
                passwd "$user"
                ;;
            [Ll]* )
                passwd -l "$user"
                echo "Account $user locked."
                ;;
            * )
                echo "No action taken for $user."
                ;;
        esac
    done
}

# Function to check and enable ASLR
enable_aslr() {
    echo "Checking if ASLR (Address Space Layout Randomization) is enabled..."

    local aslr_status=$(cat /proc/sys/kernel/randomize_va_space)

    if [ "$aslr_status" -eq 2 ]; then
        echo "ASLR is already enabled."
    else
        echo "Enabling ASLR..."
        echo 2 > /proc/sys/kernel/randomize_va_space
        # Persist the setting
        echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf
    fi
}

# Function to enable non-executable memory protection
enable_nx_protection() {
    echo "Verifying non-executable memory protection..."

    # Check if NX (No Execute) protection is enabled
    if grep -q ' nx ' /proc/cpuinfo; then
        echo "NX (No Execute) protection is enabled."
    else
        echo "NX (No Execute) protection is not enabled. Attempting to enable..."

        # Attempt to enable NX protection via kernel parameters
        if ! grep -q "noexec=off" /etc/default/grub; then
            sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="/&noexec=off /' /etc/default/grub
            update-grub
        fi

        echo "NX protection attempt complete. Please reboot and verify changes."
    fi
}

# Function to disable automatic USB mass storage mounting
disable_usb_automatic_mounting() {
    echo "Disabling automatic mounting of USB mass storage devices..."

    local udev_rule_file="/etc/udev/rules.d/100-no-usb-automount.rules"

    if [ ! -f "$udev_rule_file" ]; then
        echo 'ACTION=="add", KERNEL=="sd[a-z][0-9]", SUBSYSTEM=="block", ENV{UDISKS_IGNORE}="1"' > "$udev_rule_file"
        systemctl restart udev
        echo "Automatic USB mounting has been disabled."
    else
        echo "Automatic USB mounting is already disabled."
    fi
}

# Function to enforce a minimum 15-character password length
enforce_min_password_length() {
    echo "Enforcing a minimum 15-character password length..."

    if ! grep -q "minlen=15" /etc/pam.d/common-password; then
        # Ensure pwquality is installed and used
        apt-get install -y libpam-pwquality

        # Add or update the minlen parameter
        sed -i '/pam_pwquality.so/ s/minlen=[0-9]\+/minlen=15/' /etc/pam.d/common-password
        if ! grep -q "minlen=15" /etc/pam.d/common-password; then
            sed -i '/pam_pwquality.so/ s/$/ minlen=15/' /etc/pam.d/common-password
        fi
        echo "Minimum password length policy updated."
    else
        echo "Minimum password length of 15 characters is already enforced."
    fi
}

# Function to ensure pwquality is used for password management
enforce_pwquality() {
    echo "Ensuring pwquality is used for password management..."

    # Install pwquality if not already installed
    if ! dpkg -s libpam-pwquality &>/dev/null; then
        apt-get update
        apt-get install -y libpam-pwquality
    fi

    # Check and configure pam_pwquality
    if ! grep -q "pam_pwquality.so" /etc/pam.d/common-password; then
        # Insert pwquality line before the first password-related module
        sed -i '/password\s\+requisite\s\+pam_pwquality.so/!b;n;cpassword\trequisite\tpam_pwquality.so retry=3' /etc/pam.d/common-password
        echo "pwquality has been configured in PAM."
    else
        echo "pwquality is already configured in PAM."
    fi
}

# Function to disable accounts after 35 days of inactivity
disable_inactive_accounts() {
    echo "Disabling accounts inactive for more than 35 days..."

    # Iterate over each user
    while IFS=: read -r username _ _ last_login _; do
        # Skip if last login is not available
        if [ -z "$last_login" ] || [ "$last_login" = "never" ]; then
            continue
        fi

        # Calculate days since last login
        last_login_epoch=$(date -d "$last_login" +%s)
        current_epoch=$(date +%s)
        diff=$(( (current_epoch - last_login_epoch) / 86400 ))

        # Disable account if inactive for more than 35 days
        if [ "$diff" -gt 35 ]; then
            echo "Disabling user $username due to inactivity for $diff days."
            usermod --lock "$username"
        fi
    done < <(lastlog | awk '{print $1, $4, $5, $6}')
}

# Function to ensure secure hashing for stored passwords
ensure_secure_password_hashing() {
    echo "Ensuring all stored passwords are encrypted with a secure cryptographic hashing algorithm..."

    # Configure to use SHA-512 for password hashing
    if ! grep -q "password.*pam_unix.so.*sha512" /etc/pam.d/common-password; then
        sed -i '/password.*pam_unix.so/ s/$/ sha512/' /etc/pam.d/common-password
        echo "SHA-512 configured for password hashing."
    else
        echo "SHA-512 is already configured for password hashing."
    fi
}

# Check for auditd and configure audit rules
configure_audit_rules

# Prevent Direct Root Login
prevent_direct_root_login

# Apply Blank/Null Password Check
check_blank_passwords

# Verify and Modify Sudoers File
check_and_modify_sudoers

# Set Default Umask for All Users
set_default_umask

# Set Automatic Logout After Inactivity
set_auto_logout

# Install vlock if not present
install_vlock

# Apply SSH Hardening
harden_ssh

# Apply PAM Hardening
secure_pam

# Enable ASLR
enable_aslr

# Enable Non-Executable Memory Protection
enable_nx_protection

# Disable Automatic USB Mass Storage Mounting
disable_usb_automatic_mounting

# Enforce Minimum Password Length
enforce_min_password_length

# Enforce pwquality for Password Management
enforce_pwquality

# Disable Inactive Accounts
disable_inactive_accounts

# Ensure Secure Password Hashing
ensure_secure_password_hashing

echo "System hardening and administration tasks are complete."
