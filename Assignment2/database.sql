CREATE DATABASE IF NOT EXISTS chat_messaging;
USE chat_messaging;

CREATE TABLE IF NOT EXISTS user (
  user_id INT NOT NULL AUTO_INCREMENT,
  username VARCHAR(50) NOT NULL,
  password VARCHAR(100) NOT NULL,
  PRIMARY KEY (user_id),
  UNIQUE KEY unique_username (username)
);

CREATE TABLE IF NOT EXISTS room (
  room_id INT NOT NULL AUTO_INCREMENT,
  name VARCHAR(200) NOT NULL,
  created_datetime DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (room_id)
);

CREATE TABLE IF NOT EXISTS room_user (
  room_user_id INT NOT NULL AUTO_INCREMENT,
  user_id INT NOT NULL,
  room_id INT NOT NULL,
  last_read_message_id INT NOT NULL DEFAULT 0,
  PRIMARY KEY (room_user_id),
  UNIQUE KEY unique_room_user (user_id, room_id),
  FOREIGN KEY (user_id) REFERENCES user(user_id),
  FOREIGN KEY (room_id) REFERENCES room(room_id)
);

CREATE TABLE IF NOT EXISTS message (
  message_id INT NOT NULL AUTO_INCREMENT,
  room_user_id INT NOT NULL,
  sent_datetime DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  text TEXT NOT NULL,
  PRIMARY KEY (message_id),
  FOREIGN KEY (room_user_id) REFERENCES room_user(room_user_id)
);

CREATE TABLE IF NOT EXISTS emoji (
  emoji_id INT NOT NULL AUTO_INCREMENT,
  name VARCHAR(50) NOT NULL,
  symbol VARCHAR(10) NOT NULL,
  PRIMARY KEY (emoji_id)
);

INSERT IGNORE INTO emoji (name, symbol) VALUES
('thumbs up', '👍'),
('heart', '❤️'),
('laugh', '😂'),
('wow', '😮'),
('sad', '😢');

CREATE TABLE IF NOT EXISTS message_reaction (
  message_id INT NOT NULL,
  emoji_id INT NOT NULL,
  user_id INT NOT NULL,
  PRIMARY KEY (message_id, emoji_id, user_id),
  FOREIGN KEY (message_id) REFERENCES message(message_id),
  FOREIGN KEY (emoji_id) REFERENCES emoji(emoji_id),
  FOREIGN KEY (user_id) REFERENCES user(user_id)
);