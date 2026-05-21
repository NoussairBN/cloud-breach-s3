#IAM Role
resource "aws_iam_role" "cg-banking-WAF-Role" {
  name = "cg-banking-WAF-Role-${var.cgid}"
  assume_role_policy = jsonencode(
    {
      Version = "2012-10-17",
      Statement = [
        {
          Action = "sts:AssumeRole"
          Principal = {
            Service = "ec2.amazonaws.com"
          }
          Effect = "Allow"
          Sid    = ""
        }
      ]
    }
  )


  tags = merge(local.default_tags, {
    Name = "cg-banking-WAF-Role-${var.cgid}"
  })
}


#IAM Instance Profile
resource "aws_iam_instance_profile" "cg-ec2-instance-profile" {
  name = "cg-ec2-instance-profile-${var.cgid}"
  role = aws_iam_role.cg-banking-WAF-Role.name
}

#Security Groups
resource "aws_security_group" "cg-ec2-ssh-security-group" {
  name        = "cg-ec2-ssh-${var.cgid}"
  description = "CloudGoat ${var.cgid} Security Group for EC2 Instance over SSH"
  vpc_id      = aws_vpc.cg-vpc.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.cg_whitelist
  }

  egress {
    from_port = 0
    to_port   = 0
    protocol  = "-1"
    cidr_blocks = [
      "0.0.0.0/0"
    ]
  }

  tags = merge(local.default_tags, {
    Name = "cg-ec2-ssh-${var.cgid}"
  })
}

resource "aws_security_group" "cg-ec2-http-security-group" {
  name        = "cg-ec2-http-${var.cgid}"
  description = "CloudGoat ${var.cgid} Security Group for EC2 Instance over HTTP"
  vpc_id      = aws_vpc.cg-vpc.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = var.cg_whitelist
  }

  egress {
    from_port = 0
    to_port   = 0
    protocol  = "-1"
    cidr_blocks = [
      "0.0.0.0/0"
    ]
  }

  tags = merge(local.default_tags, {
    Name = "cg-ec2-http-${var.cgid}"
  })
}

#AWS Key Pair
resource "aws_key_pair" "cg-ec2-key-pair" {
  key_name   = "cg-ec2-key-pair-${var.cgid}"
  public_key = file(var.ssh-public-key-for-ec2)
}

#EC2 Instance
resource "aws_instance" "ec2-vulnerable-proxy-server" {
  ami                         = data.aws_ami.ubuntu.id
  instance_type               = "t3.micro"
  iam_instance_profile        = aws_iam_instance_profile.cg-ec2-instance-profile.name
  subnet_id                   = aws_subnet.cg-public-subnet-1.id
  associate_public_ip_address = true

  vpc_security_group_ids = [
    aws_security_group.cg-ec2-ssh-security-group.id,
    aws_security_group.cg-ec2-http-security-group.id
  ]

  key_name = aws_key_pair.cg-ec2-key-pair.key_name
  root_block_device {
    volume_type           = "gp2"
    volume_size           = 8
    delete_on_termination = true
  }

  provisioner "file" {
    source      = "../assets/proxy.com"
    destination = "/home/ubuntu/proxy.com"
    connection {
      type        = "ssh"
      user        = "ubuntu"
      private_key = file(var.ssh-private-key-for-ec2)
      host        = self.public_ip
    }
  }

  user_data = <<-EOF
        #!/bin/bash
        apt-get update
        apt-get install -y nginx
        ufw allow 'Nginx HTTP'
        cp /home/ubuntu/proxy.com /etc/nginx/sites-enabled/proxy.com
        rm /etc/nginx/sites-enabled/default
        systemctl restart nginx
        EOF

  volume_tags = merge(local.default_tags, {
    Name = "CloudGoat ${var.cgid} EC2 Instance Root Device"
  })

  tags = merge(local.default_tags, {
    Name = "ec2-vulnerable-proxy-server-${var.cgid}"
  })
}

# --- BLOC DE DURCISSEMENT (LEAST PRIVILEGE) ---

# 1. Création de la politique stricte
resource "aws_iam_policy" "least_privilege_s3" {
  name        = "cg-least-privilege-s3-${var.cgid}"
  description = "Politique IAM durcie limitant l'accès au bucket specifique"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.cg-cardholder-data-bucket.arn
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject"
        ]
        Resource = [
          "${aws_s3_bucket.cg-cardholder-data-bucket.arn}/*"
        ]
      }
    ]
  })
}

# 2. Attachement de la politique stricte au rôle de l'EC2
resource "aws_iam_role_policy_attachment" "least_privilege_attach" {
  role       = aws_iam_role.cg-banking-WAF-Role.name
  policy_arn = aws_iam_policy.least_privilege_s3.arn
}
