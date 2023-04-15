// a workaround for diesel_migration package to rebuild embed_migrations
// see https://github.com/diesel-rs/diesel/issues/3119
fn main() {
    println!("cargo:rerun-if-changed=migrations");
 }