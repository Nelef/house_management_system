drop database o2;
create database o2;
use o2;
create table users(
    id INT NOT NULL AUTO_INCREMENT,
    authId VARCHAR(50) NOT NULL,
    userid VARCHAR(50) NOT NULL,
    realname VARCHAR(50) NOT NULL,
    password VARCHAR(255),
    salt VARCHAR(255),
    aptname VARCHAR(50) NOT NULL,
    position VARCHAR(50) NOT NULL,
    birth VARCHAR(50) NOT NULL,
    zip VARCHAR(50) NOT NULL,
    address1 VARCHAR(50) NOT NULL,
    address2 VARCHAR(50) NOT NULL,
    phone VARCHAR(50) NOT NULL,
    PRIMARY KEY(id),
    UNIQUE (authId)
) ENGINE = InnoDB;