CREATE TABLE IF NOT EXISTS users (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  username VARCHAR(50) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  role ENUM('admin', 'pegawai') NOT NULL,
  is_active TINYINT(1) NOT NULL DEFAULT 1,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_users_username (username),
  KEY idx_users_role (role),
  KEY idx_users_is_active (is_active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS archives (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  user_id INT UNSIGNED NOT NULL,
  original_name VARCHAR(255) NOT NULL,
  stored_name VARCHAR(255) NOT NULL,
  file_ext VARCHAR(20) NOT NULL,
  original_size BIGINT UNSIGNED NOT NULL,
  encrypted_size BIGINT UNSIGNED NOT NULL,
  sha256 CHAR(64) NOT NULL,
  salt CHAR(32) NOT NULL,
  iv CHAR(32) NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_archives_user_id (user_id),
  KEY idx_archives_created_at (created_at),
  KEY idx_archives_sha256 (sha256),
  CONSTRAINT fk_archives_user_id FOREIGN KEY (user_id) REFERENCES users (id)
    ON DELETE RESTRICT ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS activity_logs (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  user_id INT UNSIGNED NOT NULL,
  archive_id INT UNSIGNED NULL,
  activity VARCHAR(100) NOT NULL,
  result VARCHAR(50) NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_activity_logs_user_id (user_id),
  KEY idx_activity_logs_archive_id (archive_id),
  KEY idx_activity_logs_created_at (created_at),
  CONSTRAINT fk_activity_logs_user_id FOREIGN KEY (user_id) REFERENCES users (id)
    ON DELETE RESTRICT ON UPDATE CASCADE,
  CONSTRAINT fk_activity_logs_archive_id FOREIGN KEY (archive_id) REFERENCES archives (id)
    ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
