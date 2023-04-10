// @generated automatically by Diesel CLI.

diesel::table! {
    stored_passwords (id) {
        id -> Integer,
        user_id -> Integer,
        purpose -> Varchar,
        password -> Varchar,
    }
}

diesel::table! {
    users (id) {
        id -> Integer,
        username -> Varchar,
        password -> Nullable<Varchar>,
        registration_type -> Varchar,
        totp_enabled -> Bool,
        totp_base32 -> Nullable<Varchar>,
    }
}

diesel::table! {
    users_oauth (id) {
        id -> Integer,
        user_id -> Integer,
        oauth_id -> Varchar,
        oauth_provider -> Varchar,
    }
}

diesel::allow_tables_to_appear_in_same_query!(stored_passwords, users, users_oauth,);
