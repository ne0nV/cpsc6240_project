#!/bin/bash

# Enhanced Linux Hardening and Administration Script for Ubuntu LTS

# Ensure the script is run as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

# Update and Upgrade the System
echo "Updating and Upgrading the System..."
apt-get update && apt-get upgrade -y
apt-get dist-upgrade -y
apt-get autoremove -y

# Install Essential Security Packages
echo "Installing essential security packages..."
apt-get install -y unattended-upgrades fail2ban ufw

# Enable and Configure Firewall
echo "Configuring UFW (Uncomplicated Firewall)..."
ufw enable
ufw default deny incoming
ufw default allow outgoing
# Add additional rules as needed, e.g., ufw allow ssh

# Configure Automatic Security Updates
echo "Configuring automatic security updates..."
cat > /etc/apt/apt.conf.d/20auto-upgrades << EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF

# Function to manage sudo group members
manage_sudo_users() {
    echo "Auditing sudo group members..."
    local users=$(getent group sudo | cut -d: -f4)
    local user_array=(${users//,/ })
    
    for user in "${user_array[@]}"; do
        echo "Do you want to keep $user in the sudo group? [y/N]"
        read -r response
        if [[ "$response" =~ ^([nN][oO]|[nN])$ ]]; then
            deluser "$user" sudo
            echo "$user removed from sudo group."
        else
            echo "$user kept in sudo group."
        fi
    done
}

# Function to check and modify sudoers file
check_and_modify_sudoers() {
    echo "Verifying and modifying /etc/sudoers and /etc/sudoers.d..."

    # Check and modify /etc/sudoers
    if grep -Eqs 'NOPASSWD|!authenticate' /etc/sudoers; then
        echo "Found 'NOPASSWD' or '!authenticate' in /etc/sudoers. Removing..."
        sed -i '/NOPASSWD/d' /etc/sudoers
        sed -i '/!authenticate/d' /etc/sudoers
    fi

    # Check and modify files in /etc/sudoers.d
    for file in /etc/sudoers.d/*; do
        if grep -Eqs 'NOPASSWD|!authenticate' "$file"; then
            echo "Found 'NOPASSWD' or '!authenticate' in $file. Removing..."
            sed -i '/NOPASSWD/d' "$file"
            sed -i '/!authenticate/d' "$file"
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

# Log Auditing (Auditd)
echo "Installing and configuring auditd..."
apt-get install -y auditd
# Configure as necessary

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

# Apply Blank/Null Password Check
check_blank_passwords

# Verify and Modify Sudoers File
check_and_modify_sudoers

# Set Default Umask for All Users
set_default_umask

# Apply SSH Hardening
harden_ssh

# Apply PAM Hardening
secure_pam

echo "System hardening and basic administration tasks are complete."
