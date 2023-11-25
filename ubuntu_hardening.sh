#!/bin/bash

# Enhanced Linux Hardening and Administration Script for Ubuntu LTS

# Ensure the script is run as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

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
# systemctl disable <service-name>

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

echo "System hardening and basic administration tasks are complete."

