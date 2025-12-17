######################################################
#VPC (NetWork Layer)
######################################################

resource "aws_vpc" "WebApp-vpc" {
  cidr_block = "10.0.0.0/16"

}
######################################################
#internet gateway
######################################################
resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.WebApp-vpc.id
  tags = {
    Name = "main"
  }
}
######################################################
# Subnets (Multi-AZ)
######################################################

resource "aws_subnet" "public_subnet_az1" {
  vpc_id                  = aws_vpc.WebApp-vpc.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "us-east-1a"
  map_public_ip_on_launch = true

  tags = {
    Name = "Public-Subnet-AZ1"
  }
}

resource "aws_subnet" "public_subnet_az2" {
  vpc_id                  = aws_vpc.WebApp-vpc.id
  cidr_block              = "10.0.3.0/24"
  availability_zone       = "us-east-1b"
  map_public_ip_on_launch = true

  tags = {
    Name = "Public-Subnet-AZ2"
  }
}

resource "aws_subnet" "private_subnet_az1" {
  vpc_id            = aws_vpc.WebApp-vpc.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "us-east-1a"

  tags = {
    Name = "Private-Subnet-AZ1"
  }
}

resource "aws_subnet" "private_subnet_az2" {
  vpc_id            = aws_vpc.WebApp-vpc.id
  cidr_block        = "10.0.4.0/24"
  availability_zone = "us-east-1b"

  tags = {
    Name = "Private-Subnet-AZ2"
  }
}

######################################################
#route_tables
######################################################
resource "aws_route_table" "public_route_table" {
  vpc_id = aws_vpc.WebApp-vpc.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gw.id
  }
  tags = {
    Name = "Public route table"
  }
}
resource "aws_route_table_association" "public_route_table_association" {
  subnet_id      = aws_subnet.public_subnet_az1.id
  route_table_id = aws_route_table.public_route_table.id
}


resource "aws_route_table" "Private_route_table" {
  vpc_id = aws_vpc.WebApp-vpc.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.project.id
  }
  tags = {
    Name = "Private route table"
  }
}
######################################################
#nat_gateway
######################################################
resource "aws_nat_gateway" "project" {
  allocation_id = aws_eip.nat_eip.id
  subnet_id     = aws_subnet.public_subnet_az1.id
  tags = {
    Name = "gw NAT"
  }

  # To ensure proper ordering, it is recommended to add an explicit dependency
  # on the Internet Gateway for the VPC.
  depends_on = [aws_internet_gateway.gw]
}
# Elastic IP for NAT
resource "aws_eip" "nat_eip" {
  tags = {
    Name = "nat-eip"
  }
}

output "vpc_id" {
  value = aws_vpc.WebApp-vpc.id
}

output "nat_gateway_id" {
  value = aws_nat_gateway.project
}
#######################################################################################################################
#Compute Layer (EC2 ,Security Group ,ALB )
#######################################################################################################################

resource "aws_security_group" "alb_sg" {
  vpc_id = aws_vpc.WebApp-vpc.id

  # Allow public traffic to ALB
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Allow ALB to send traffic (to EC2)
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}


resource "aws_security_group" "ec2_sg" {
  vpc_id = aws_vpc.WebApp-vpc.id

  # EC2 receives traffic from ALB only
  ingress {
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id]
  }

  # EC2 outbound allowed (Internet via NAT)
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "rds_sg" {
  name   = "rds-sg"
  vpc_id = aws_vpc.WebApp-vpc.id

  # Allow DB access only from EC2 SG
  ingress {
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.ec2_sg.id]
  }

  # Outbound allowed (عادة مفتوح)
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "RDS-SG"
  }
}


resource "aws_lb_target_group" "alb_tg" {
  name        = "lb-alb-tg"
  target_type = "instance"
  port        = 80
  protocol    = "HTTP"
  vpc_id      = aws_vpc.WebApp-vpc.id

  # Health Check
  health_check {
    enabled             = true
    protocol            = "HTTP"
    port                = "traffic-port"
    path                = "/"
    healthy_threshold   = 2
    unhealthy_threshold = 2
    timeout             = 5
    interval            = 30
    matcher             = "200-399"
  }

  tags = {
    Name = "ALB-TG"
  }
}
resource "aws_lb" "application_alb" {
  name               = "webapp-alb"
  load_balancer_type = "application"
  internal           = false # لأنه Public ALB
  security_groups    = [aws_security_group.alb_sg.id]
  subnets = [
    aws_subnet.public_subnet_az1.id,
    aws_subnet.public_subnet_az2.id
  ]


  ip_address_type = "ipv4"

  tags = {
    Name = "WebApp-ALB"
  }
}
resource "aws_lb_listener" "alb_listener" {
  load_balancer_arn = aws_lb.application_alb.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.alb_tg.arn
  }
}
resource "aws_launch_template" "lt" {
  name = "webapp-launch-template"

  image_id                = "ami-0c7217cdde317cfec" # مثال Amazon Linux 2
  instance_type           = "t2.micro"
  ebs_optimized           = true
  disable_api_stop        = true
  disable_api_termination = true

  monitoring {
    enabled = true
  }

  network_interfaces {
    associate_public_ip_address = false
    security_groups             = [aws_security_group.ec2_sg.id]
  }

  tag_specifications {
    resource_type = "instance"

    tags = {
      Name = "WebApp-EC2"
    }
  }


  user_data = base64encode(<<EOF
#!/bin/bash
sudo amazon-linux-extras install nginx1 -y
sudo systemctl start nginx
sudo systemctl enable nginx
EOF
  )
}

resource "aws_autoscaling_group" "webapp_asg" {
  name             = "webapp-asg"
  min_size         = 2
  max_size         = 2
  desired_capacity = 2

  vpc_zone_identifier = [
    aws_subnet.private_subnet_az1.id,
    aws_subnet.private_subnet_az2.id
  ]


  target_group_arns = [
    aws_lb_target_group.alb_tg.arn
  ]

  health_check_type         = "ELB"
  health_check_grace_period = 300

  launch_template {
    id      = aws_launch_template.lt.id
    version = "$Latest"
  }

  tag {
    key                 = "Name"
    value               = "WebApp-ASG-Instance"
    propagate_at_launch = true
  }
}

#######################################################################################################################
#DataBacse Layer (AWS_RDS)
#######################################################################################################################

resource "aws_db_subnet_group" "rds_subnet_group" {
  name = "rds-subnet-group"

  subnet_ids = [
    aws_subnet.private_subnet_az1.id,
    aws_subnet.private_subnet_az2.id
  ]

  tags = {
    Name = "RDS Subnet Group"
  }
}
resource "aws_db_instance" "webapp_rds" {
  identifier = "webapp-db"

  engine         = "mysql"
  engine_version = "8.0"
  instance_class = "db.t3.micro"

  allocated_storage = 20
  storage_type      = "gp2"

  db_name  = "webappdb"
  username = "admin"
  password = "StrongPassword123!" # يفضل variable أو secrets manager

  multi_az = true

  db_subnet_group_name = aws_db_subnet_group.rds_subnet_group.name
  vpc_security_group_ids = [
    aws_security_group.rds_sg.id
  ]

  publicly_accessible = false

  backup_retention_period = 7
  skip_final_snapshot     = true

  deletion_protection = false

  tags = {
    Name = "WebApp-RDS"
  }
}
#######################################################################################################################
#IAM Layer (policies,Security,permissions)
#######################################################################################################################
resource "aws_iam_role" "ec2_role" {
  name = "ec2-webapp-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "cloudwatch" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}
resource "aws_iam_role_policy_attachment" "s3_access" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
}
resource "aws_iam_instance_profile" "ec2_profile" {
  name = "ec2-webapp-profile"
  role = aws_iam_role.ec2_role.name
}



#######################################################################################################################
#Monitoring & Auto Scaling Layer (cloudwatch_log_group - cloudwatch_metric_alarm - autoscaling_policy)
#######################################################################################################################

resource "aws_cloudwatch_log_group" "webapp_logs" {
  name              = "/webapp/ec2"
  retention_in_days = 14

  tags = {
    Name = "WebApp-Logs"
  }
}
resource "aws_autoscaling_policy" "cpu_scaling_policy" {
  name                   = "cpu-target-tracking"
  autoscaling_group_name = aws_autoscaling_group.webapp_asg.name
  policy_type            = "TargetTrackingScaling"

  target_tracking_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ASGAverageCPUUtilization"
    }

    target_value = 60.0
  }
}
resource "aws_cloudwatch_metric_alarm" "high_cpu_alarm" {
  alarm_name          = "webapp-high-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 120
  statistic           = "Average"
  threshold           = 80

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.webapp_asg.name
  }

  alarm_description = "High CPU usage on WebApp ASG"
}
