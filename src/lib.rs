#[cfg(test)]
mod tests;

use base64_kenji::base64_encode;

pub struct JWT {
    headers: Vec<[String;2]>,
    payload: Vec<[String;2]>,
    secret: String
}

impl JWT {
    pub fn new(secret: String) -> Self {
        JWT {
            headers: Vec::new(),
            payload: Vec::new(),
            secret
        }
    }

    pub fn verify(jwt: String, secret: String) -> bool {
        let mut parts = jwt.split(".");
        let headers = match parts.next() {
            Some(headers) => headers.to_string(),
            None => return false
        };
        let payload = match parts.next() {
            Some(payload) => payload.to_string(),
            None => return false
        };

        let correct_jwt = Self::jwt_to_string(headers.clone(), payload, secret);

        jwt == correct_jwt
    }

    pub fn build(self) -> String {
        let headers = base64_encode(Self::build_json(self.headers));
        let payload = base64_encode(Self::build_json(self.payload));

        Self::jwt_to_string(headers, payload, self.secret)
    }

    pub fn add_header(mut self, key: &str, value: &str) -> Self {
        self.headers.push([key.to_string(), value.to_string()]);
        self
    }
    pub fn add_payload(mut self, key: &str, value: &str) -> Self {
        self.payload.push([key.to_string(), value.to_string()]);
        self
    }

    fn jwt_to_string(headers: String, payload: String, secret: String) -> String {
        let hash_input = format!("{}.{}.{}", headers, payload, secret);

        format!("{}.{}.{}", headers, payload, Self::hash(hash_input, secret))
    }

    fn build_json(values: Vec<[String;2]>) -> String {
        let mut res: String = values.into_iter().map(|[key, value]| {
            format!(r#""{}":"{}","#, key, value)
        }).collect::<String>();

        res.pop();

        format!("{{{}}}", res)
    }

    fn hash(input: String, secret: String) -> String {
        let options: [char;69] = ['A','B','C','D','E','F','G','H','I','J','K','L','M',
            'N','O','P','Q','R','S','T','U','V','W','X','Y','Z','a','b','c',
            'd','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s',
            't','u','v','w','x','y','z','0','1','2','3','4','5','6','7','8'
            ,'9','+','/','%','/','*','"','='];

        let mut hash_bytes: [char;30] = ['_';30];
        let input_bytes = input.into_bytes();
        let secret_bytes = secret.into_bytes();

        let mut input_idx = 0;
        let mut secret_idx = 0;

        for i in 0..30 {
            if input_idx >= input_bytes.len() {
                input_idx = 0;
            }
            if secret_idx >= secret_bytes.len() {
                secret_idx = 0;
            }

            hash_bytes[i] = options[((input_bytes[input_idx] + secret_bytes[secret_idx]) % 69) as usize];

            input_idx += 1;
            secret_idx += 1;
        }

        hash_bytes.into_iter().collect()
    }
}

