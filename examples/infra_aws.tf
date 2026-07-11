# Demo Terraform-like snippet for cost auditing

resource "aws_instance" "web" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "m5.xlarge"
  count         = 2

  tags = {
    Name = "web"
  }
}

resource "aws_instance" "worker" {
  instance_type = "t3.medium"
}

resource "aws_db_instance" "primary" {
  instance_class = "db.m5.large"
  engine         = "postgres"
}
