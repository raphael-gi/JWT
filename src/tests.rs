use super::JWT;

#[test]
fn test_build_jwt() {
    let jwt = JWT::new("this is my secret".to_string())
        .add_header("alg", "HS256")
        .add_header("typ", "JWT")
        .add_payload("sub", "1234567890")
        .add_payload("name", "John Doe")
        .add_payload("iat", "1516239022")
        .build();

    let mut parts = jwt.split(".");

    let headers = parts.next().unwrap();
    assert_eq!(headers, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9");

    let payload = parts.next().unwrap();
    assert_eq!(payload, "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoiMTUxNjIzOTAyMiJ9");
}

#[test]
fn test_verify_jwt() {
    let jwt = JWT::new("heheheha".to_string())
        .add_header("alg", "HS256")
        .build();

    assert!(JWT::verify(jwt.clone(), "heheheha".to_string()));

    let faulty_jwt = jwt.replace("e", "a");
    assert!(!JWT::verify(faulty_jwt, "heheheha".to_string()));
}

