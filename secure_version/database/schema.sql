
CREATE TABLE sectors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sectorName VARCHAR(80) NOT NULL UNIQUE
);


CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(80) NOT NULL UNIQUE,
    email VARCHAR(120) NOT NULL,
    password VARCHAR(200) NOT NULL,
    password_history JSON,
    failed_attempts INTEGER DEFAULT 0,
    is_locked BOOLEAN DEFAULT FALSE,
    sector_id INTEGER NOT NULL,
    reset_token VARCHAR(200),
    FOREIGN KEY (sector_id) REFERENCES sectors(id) 
);

CREATE TABLE customers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name VARCHAR(80) NOT NULL,
    email VARCHAR(120) NOT NULL,
    sector_id INTEGER NOT NULL,
    FOREIGN KEY (sector_id) REFERENCES sectors(id)
)