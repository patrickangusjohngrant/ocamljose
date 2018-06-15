#require "core";;
#require "base64";;
#require "yojson";;
#require "digestif.ocaml";;

open Core

let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.Avs9ToI84RCkFm1UAXidLfTaJZHvNg_0R1UIQu0YHAc";;

let base64url_decode input =
    let padding = match String.length input % 4 with
    | 0 -> ""
    | n -> String.init (4 - n) (fun _ -> '=')
    in
    let safe_input =
        String.map
            input
            ~f:(function '_' -> '+' | c -> c)
    in
    let padded = String.concat [
        safe_input;
        padding
    ]
    in
    B64.decode padded;;

let base64url_encode input =
    B64.encode input |>
    String.map ~f:(function '/' -> '+' | c -> c) |>
    String.rstrip ~drop:((=) '=');;

let load jwt =
    let signing_input, crypto_segment = String.rsplit2_exn ~on:'.' jwt
    in
    let header_segment, claims_segment = String.lsplit2_exn ~on:'.' signing_input
    in
    let header_data = base64url_decode header_segment
    in
    let header = Yojson.Basic.from_string header_data
    in
    let payload = base64url_decode claims_segment
    in
    let signature = base64url_decode crypto_segment
    in
    (header, payload, signing_input, signature)
;;

let json_to_digestif_hash header =
    let open Yojson.Basic.Util in
    match filter_member "alg" [ header ] |> filter_string with
    | [ "HS256" ] -> `SHA256
    | _ -> assert false;;

let verify_signature header secret body signature =
    let hmac = Digestif.Bytes.mac (json_to_digestif_hash header) ~key:secret body
    in
    let expected_signature = hmac
    in
    assert (String.equal
        (base64url_encode expected_signature)
        (base64url_encode signature));;

let jws_verify token key =
    let header, payload, signing_input, signature = load token
    in
    verify_signature header key signing_input signature
