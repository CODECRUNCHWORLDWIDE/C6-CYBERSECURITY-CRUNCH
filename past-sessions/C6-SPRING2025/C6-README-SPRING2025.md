# Course Content - Spring 2025

---

# Week - 0 

## Topics: Introduction To Cybersecurity
- **Week Dates:** January 6, 2025 - January 10, 2025
- **Unit:** Week 0 - Overview of C6 and TryHackme
- **Link to Slides:** [Week 0 - C6 _ Cyber Crunch.pptx](https://github.com/CODECRUNCHWORLDWIDE/C6-CYBERSECURITY-CRUNCH/blob/main/C6-SPRING2025/C6-RESOURCES/Week%200%20-%20C6%20_%20Cyber%20Crunch.pptx.pdf)

### **Commands: Terminal**
```bash
# List files in the current directory
ls

# Change directory
cd /path/to/directory

# Create a new directory
mkdir new_directory

# Remove a file
rm file_name.txt

# Check current working directory
pwd
```

---

# Week - 1

## Topics: Introduction To Cybersecurity
- **Week Dates:** January 13, 2025 - January 17, 2025
- **Units:** 
    - Unit 1 - Introduction to Cybersecurity
- **Link to content:**
    - [Introduction to Cybersecurity](https://github.com/CODECRUNCHWORLDWIDE/C6-CYBERSECURITY-CRUNCH/blob/main/C6-SPRING2025/C6-RESOURCES/Week%201%20-%20C6%20_%20Cyber%20Crunch.pptx.pdf)

### **Sample block of code: Commands: Terminal**
```bash
# Sample block of commands
ls -la
cd ..
pwd
```

---

# Week - 2

## Topics: TryHackMe Basics
- **Week Dates:** January 20, 2025 - January 24, 2025
- **Unit:** Week 2 - TryHackMe Basics
- **Link to Slides:** [Week 2 - C6 _ Cyber Crunch.pptx](https://docs.google.com)

### **Commands: Terminal**
```bash
# Display network information
ifconfig

# Ping a website to test connectivity
ping google.com

# Check open ports
netstat -tuln
```

---

# Week - 3

## Topics: Linux Essentials
- **Week Dates:** January 27, 2025 - January 31, 2025
- **Unit:** Week 3 - Linux Essentials
- **Link to Slides:** [Week 3 - Linux Essentials.pptx](https://docs.google.com)

### **Commands: Terminal**
```bash
# Update Linux packages
sudo apt update && sudo apt upgrade

# Create a symbolic link
ln -s /path/to/file /path/to/symlink

# View file permissions
ls -l
```

---

# Week - 4

## Topics: Networking Fundamentals
- **Week Dates:** February 3, 2025 - February 7, 2025
- **Unit:** Week 4 - Networking Basics
- **Link to Slides:** [Week 4 - Networking Basics.pptx](https://docs.google.com)

### **Commands: Terminal**
```bash
# Display active connections
netstat -an

# Trace route to a host
traceroute google.com

# View ARP table
arp -a
```

---

# Week - 5

## Topics: Cryptography Basics
- **Week Dates:** February 10, 2025 - February 14, 2025
- **Unit:** Week 5 - Cryptography Basics
- **Link to Slides:** [Week 5 - Cryptography Basics.pptx](https://docs.google.com)

### **Commands: Terminal**
```bash
# Encrypt a file using OpenSSL
openssl enc -aes-256-cbc -in file.txt -out file.enc

# Decrypt a file using OpenSSL
openssl enc -d -aes-256-cbc -in file.enc -out file.txt

# Generate an RSA key pair
openssl genrsa -out private.key 2048
```

---

# Week - 6

## Topics: Web Security
- **Week Dates:** February 17, 2025 - February 21, 2025
- **Unit:** Week 6 - Web Security
- **Link to Slides:** [Week 6 - Web Security.pptx](https://docs.google.com)

### **Commands: Terminal**
```bash
# Start a simple HTTP server
python3 -m http.server 8080

# Test HTTP headers
curl -I http://example.com

# Scan a website for vulnerabilities (using Nikto)
nikto -h http://example.com
```

---

# Week - 7

## Topics: Spring Break
- **Week Dates:** February 24, 2025 - February 28, 2025
- **Unit:** Spring Break (No Classes)

---

# Week - 8

## Topics: Incident Response
- **Week Dates:** March 3, 2025 - March 7, 2025
- **Unit:** Week 8 - Incident Response Overview
- **Link to Slides:** [Week 8 - Incident Response.pptx](https://docs.google.com)

### **Commands: Terminal**
```bash
# Monitor live logs
tail -f /var/log/syslog

# Capture network packets
tcpdump -i eth0

# Analyze log files
cat /var/log/auth.log | grep "failed"
```

---

# Week - 9

## Topics: Forensics Basics
- **Week Dates:** March 10, 2025 - March 14, 2025
- **Unit:** Week 9 - Digital Forensics Essentials
- **Link to Slides:** [Week 9 - Digital Forensics.pptx](https://docs.google.com)

### **Commands: Terminal**
```bash
# Create a disk image
sudo dd if=/dev/sdX of=image.img bs=1M

# Verify file hash
sha256sum file.img

# Extract metadata from a file
exiftool file.jpg
```

---

# Week - 10

## Topics: Vulnerability Assessment
- **Week Dates:** March 17, 2025 - March 21, 2025
- **Unit:** Week 10 - Vulnerability Scanning Tools
- **Link to Slides:** [Week 10 - Vulnerability Assessment.pptx](https://docs.google.com)

### **Commands: Terminal**
```bash
# Scan a network using Nmap
nmap -sS -p 1-65535 192.168.1.1

# Perform a vulnerability scan (OpenVAS)
gvm-cli socket --xml "<XML request here>"

# List installed packages for vulnerabilities
dpkg --get-selections
```

---

# Week - 11

## Topics: Capstone Project Preparation
- **Week Dates:** March 24, 2025 - April 4, 2025
- **Unit:** Week 11 - Capstone Project Overview and Final Prep
- **Link to Slides:** [Week 11 - Capstone Overview.pptx](https://docs.google.com)

### **Commands: Terminal**
```bash
# Initialize a Git repository
git init

# Add files to the repository
git add .

# Commit changes
git commit -m "Initial commit"
```

---
