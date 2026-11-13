# AWS EC2 Production Deployment Guide
## Cloud-Based Smart Parking Management System

This guide outlines the step-by-step procedure to deploy the Smart Parking backend and web interface to an Amazon EC2 instance.

---

### Step 1: Launch EC2 Instance & Configure Security Groups

1. Log in to the [AWS Management Console](https://console.aws.amazon.com/ec2).
2. Choose **Launch Instances**:
   - **Name:** `SmartParking-Backend-Server`
   - **AMI:** Ubuntu Server 22.04 LTS (HVM), SSD Volume Type (64-bit x86)
   - **Instance Type:** `t3.micro` (Eligible for AWS Free Tier) or `t3.small`
   - **Key Pair:** Select or generate an RSA key pair (`smart-parking-key.pem`).
3. **Configure Security Group (`SmartParking-SG`):**
   - **Inbound Rules:**
     | Type | Protocol | Port Range | Source | Description |
     | :--- | :--- | :--- | :--- | :--- |
     | SSH | TCP | 22 | My IP | Secure administrative terminal access |
     | HTTP | TCP | 80 | 0.0.0.0/0 | Public web traffic & Let's Encrypt challenge |
     | HTTPS | TCP | 443 | 0.0.0.0/0 | Secure web traffic |
     | Custom TCP | TCP | 5000 | 0.0.0.0/0 (Optional) | Direct testing port (can be closed once Nginx is configured) |

---

### Step 2: Create & Attach IAM Role for DynamoDB Access

To satisfy the **Security Requirement** that no AWS Access Keys or Secret Keys are stored in the server `.env`, attach an IAM role directly to the EC2 instance:

1. Navigate to **AWS IAM Console** > **Roles** > **Create Role**.
2. Select **AWS Service** and choose **EC2**.
3. Attach Policy or create inline policy `SmartParkingDynamoDBPolicy`:
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": [
           "dynamodb:GetItem",
           "dynamodb:PutItem",
           "dynamodb:UpdateItem",
           "dynamodb:DeleteItem",
           "dynamodb:Scan",
           "dynamodb:Query",
           "dynamodb:DescribeTable",
           "dynamodb:BatchWriteItem",
           "dynamodb:TransactWriteItems"
         ],
         "Resource": [
           "arn:aws:dynamodb:*:*:table/ParkingSlots",
           "arn:aws:dynamodb:*:*:table/ParkingSlots/*",
           "arn:aws:dynamodb:*:*:table/Bookings",
           "arn:aws:dynamodb:*:*:table/Bookings/*",
           "arn:aws:dynamodb:*:*:table/DetectionHistory",
           "arn:aws:dynamodb:*:*:table/DetectionHistory/*"
         ]
       }
     ]
   }
   ```
4. Name the role `SmartParkingEC2Role` and create it.
5. In the EC2 Console, select your instance > **Actions** > **Security** > **Modify IAM Role** > Attach `SmartParkingEC2Role`.

---

### Step 3: Connect to EC2 & Install Runtime Dependencies

Connect to the instance via SSH:
```bash
chmod 400 smart-parking-key.pem
ssh -i "smart-parking-key.pem" ubuntu@<YOUR_EC2_PUBLIC_DNS_OR_IP>
```

Update package repositories and install Node.js (v22 LTS), Git, Nginx, and build essentials:
```bash
sudo apt update && sudo apt upgrade -y
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt install -y nodejs git nginx build-essential

# Verify versions
node -v
npm -v
```

Install PM2 globally for production process management:
```bash
sudo npm install -g pm2
```

---

### Step 4: Clone Repository & Configure Environment

Clone the repository into `/var/www`:
```bash
sudo mkdir -p /var/www
sudo chown -R ubuntu:ubuntu /var/www
cd /var/www
git clone https://github.com/<YOUR_GITHUB_USERNAME>/cloud-smart-parking-system.git
cd cloud-smart-parking-system/backend

# Install production dependencies
npm install --production
```

Create production `.env` file:
```bash
cat << 'EOF' > .env
PORT=5000
NODE_ENV=production
DB_MODE=aws
AWS_REGION=us-east-1

# Tables
DYNAMODB_TABLE_PARKING_SLOTS=ParkingSlots
DYNAMODB_TABLE_BOOKINGS=Bookings
DYNAMODB_TABLE_DETECTION_HISTORY=DetectionHistory

# Admin Authentication
ADMIN_API_KEY=super-secret-admin-key-ec2-2026
JWT_SECRET=production-smart-parking-jwt-token
EOF
```

Initialize DynamoDB tables:
```bash
node scripts/setupDynamoDB.js
node scripts/seedData.js
```

---

### Step 5: Start Application with PM2

Start the Node.js server with PM2:
```bash
pm2 start server.js --name "smart-parking"
pm2 save
pm2 startup
# Follow on-screen instruction to register systemd service
```

Check process health:
```bash
pm2 status
pm2 logs smart-parking
```

---

### Step 6: Configure Nginx Reverse Proxy

Create an Nginx configuration file:
```bash
sudo nano /etc/nginx/sites-available/smartparking
```

Add the following block:
```nginx
server {
    listen 80;
    server_name <YOUR_DOMAIN_OR_EC2_PUBLIC_IP>;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

Enable the configuration and reload Nginx:
```bash
sudo ln -s /etc/nginx/sites-available/smartparking /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t
sudo systemctl restart nginx
```

---

### Step 7: Verification

Visit `http://<YOUR_EC2_PUBLIC_IP>` in your browser to access the web dashboard!
Verify health endpoint:
```bash
curl http://<YOUR_EC2_PUBLIC_IP>/api/health
```
Output:
```json
{
  "status": "HEALTHY",
  "service": "Cloud Smart Parking API",
  "version": "1.0.0",
  "databaseMode": "aws",
  "timestamp": "2026-11-13T22:30:00.000Z"
}
```
