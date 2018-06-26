#require "core";;
#require "base64";;
#require "yojson";;
#require "digestif.ocaml";;

open Core;;

module Util =
struct
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
end

module Jws : sig
    type t 
    val load : string -> string -> t
(* TODO: move verify into load *)
(* TODO: 
    val extract : t -> jwt_member list
    val to_string -> algorithm -> key -> t -> string
*)
end =
struct
    type t = {
        hash: Digestif.hash;
        claims: (string * string) list
    };;

    let header_to_digestif_hash header =
        let open Yojson.Basic.Util in
        match filter_member "alg" [ Yojson.Basic.from_string header ] |> filter_string with
        | [ "HS256" ] -> `SHA256
        | _ -> assert false;;

    let verify_signature hash secret body signature =
        let expected = Digestif.Bytes.mac hash ~key:secret body
        in
        assert (String.equal
            (Util.base64url_encode expected)
            (Util.base64url_encode signature));;

    let parse_claims data = match Yojson.Basic.from_string data with
        | `Assoc l -> List.map ~f:(function (k, `String v) -> (k, v) | _ -> assert false) l
        | _ -> assert false;;
 
    let load secret jwt : t =
        let signing_input, crypto_segment = String.rsplit2_exn ~on:'.' jwt
        in
        let header_segment, claims_segment = String.lsplit2_exn ~on:'.' signing_input
        in
        let header_data = Util.base64url_decode header_segment
        in
        let hash = header_to_digestif_hash header_data
        in
        let claims_data = Util.base64url_decode claims_segment
        in
        let signature = Util.base64url_decode crypto_segment
        in
        let () = verify_signature hash secret signing_input signature
        in
        let claims = parse_claims claims_data
        in
        {
            hash=hash;
            claims=claims
        }

end

let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.Avs9ToI84RCkFm1UAXidLfTaJZHvNg_0R1UIQu0YHAc";;

Jws.load "test" token;;

