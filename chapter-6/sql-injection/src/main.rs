#[macro_use]
extern crate rocket;
use rocket::Error;

use rocket::form::Form;
use rocket_db_pools::sqlx::{self, Row};
use rocket_db_pools::{Connection, Database};

#[derive(Database)]
#[database("sqlite_db")]
struct DbConn(sqlx::SqlitePool);

#[derive(Debug, FromForm)]
struct UserData {
    username: String,
    password: String,
}

#[post("/login", data = "<user_data>")]
async fn login(mut conn: Connection<DbConn>, user_data: Form<UserData>) -> Result<String, String> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS users (
          username TEXT,
          password TEXT
        );"#,
    )
    .execute(&mut **conn)
    .await
    .unwrap();

    let username = &user_data.username;
    let password = &user_data.password;

    let query_result = sqlx::query(&format!(
        "SELECT * FROM users WHERE username = '{}' AND password = '{}'",
        username, password
    ))
    .fetch_one(&mut **conn)
    .await
    .and_then(|r| {
        let username: Result<String, _> = Ok::<String, Error>(r.get::<String, _>(0));
        let password: Result<String, _> = Ok::<String, Error>(r.get::<String, _>(1));
        Ok((username, password))
    })
    .ok();

    match query_result {
        Some((username, password)) => Ok(format!(
            "username: {}, password: {}",
            username.unwrap(),
            password.unwrap()
        )),
        None => Err("User not found".into()),
    }
}

#[post("/register", data = "<user_data>")]
async fn register(
    mut conn: Connection<DbConn>,
    user_data: Form<UserData>,
) -> Result<String, String> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS users (
          username TEXT,
          password TEXT
        );"#,
    )
    .execute(&mut **conn)
    .await
    .unwrap();

    let username = &user_data.username;
    let password = &user_data.password;

    sqlx::query("INSERT INTO users (username, password) VALUES (?, ?)")
        .bind(username)
        .bind(password)
        .execute(&mut **conn)
        .await
        .unwrap();

    Ok("Signed up successfully!".to_string())
}

#[launch]
fn rocket() -> _ {
    rocket::build()
        .attach(DbConn::init())
        .mount("/", routes![register, login])
}
