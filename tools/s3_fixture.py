import hashlib
import hmac
import http.server
import json
import os
import sys
import threading
import time
import urllib.parse
import xml.etree.ElementTree as ET


ACCESS = "AKIAIOSFODNN7EXAMPLE"
SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
TOKEN = "session+/="


def encoded(value):
    return urllib.parse.quote(value, safe="-_.~")


def digest(key, value):
    return hmac.new(key, value.encode(), hashlib.sha256).digest()


class Fixture(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    objects = {}
    uploads = {}
    aborted = 0
    redirected = 0
    checked = 0

    def log_message(self, *args):
        pass

    def reply(self, code, body=b"", headers=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def verified(self, body):
        target = urllib.parse.urlsplit(self.path)
        pairs = urllib.parse.parse_qsl(target.query, keep_blank_values=True)
        query = dict(pairs)
        presigned = "X-Amz-Signature" in query
        if presigned:
            signature = query["X-Amz-Signature"]
            credential = query["X-Amz-Credential"]
            names = query["X-Amz-SignedHeaders"]
            date = query["X-Amz-Date"]
            assert query["X-Amz-Algorithm"] == "AWS4-HMAC-SHA256"
            assert query["X-Amz-Security-Token"] == TOKEN
            assert 1 <= int(query["X-Amz-Expires"]) <= 604800
            pairs = [(k, v) for k, v in pairs if k != "X-Amz-Signature"]
            payload = "UNSIGNED-PAYLOAD"
        else:
            scheme, fields = self.headers["Authorization"].split(" ", 1)
            assert scheme == "AWS4-HMAC-SHA256"
            values = dict(part.strip().split("=", 1) for part in fields.split(","))
            signature = values["Signature"]
            credential = values["Credential"]
            names = values["SignedHeaders"]
            date = self.headers["X-Amz-Date"]
            assert self.headers["X-Amz-Security-Token"] == TOKEN
            payload = hashlib.sha256(body).hexdigest()
            assert self.headers["X-Amz-Content-Sha256"] == payload
            for key in self.headers:
                if key.lower().startswith("x-amz-"):
                    assert key.lower() in names.split(";")
        access, scope = credential.split("/", 1)
        assert access == ACCESS
        assert scope == "20130524/us-east-1/s3/aws4_request"
        assert date == "20130524T000000Z"
        assert names.split(";") == sorted(set(names.split(";")))
        canonical_headers = ""
        for name in names.split(";"):
            values = [" ".join(value.split()) for value in self.headers.get_all(name)]
            canonical_headers += name + ":" + ",".join(values) + "\n"
        canonical_query = "&".join(k + "=" + v for k, v in sorted((encoded(k), encoded(v)) for k, v in pairs))
        canonical_path = urllib.parse.quote(urllib.parse.unquote(target.path), safe="/-_.~")
        canonical = "\n".join([self.command, canonical_path, canonical_query, canonical_headers, names, payload])
        text = "\n".join(["AWS4-HMAC-SHA256", date, scope, hashlib.sha256(canonical.encode()).hexdigest()])
        key = ("AWS4" + SECRET).encode()
        for part in scope.split("/"):
            key = digest(key, part)
        assert hmac.compare_digest(signature, digest(key, text).hex())
        Fixture.checked += 1
        return urllib.parse.unquote(target.path), query

    def dispatch(self):
        if self.path == "/stats":
            self.reply(200, json.dumps({"checked": Fixture.checked, "aborted": Fixture.aborted, "redirected": Fixture.redirected}))
            return
        if self.path == "/leak":
            Fixture.redirected += 1
            self.reply(500)
            return
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        try:
            path, query = self.verified(body)
        except Exception:
            self.reply(403, "<Error><Code>SignatureDoesNotMatch</Code></Error>")
            return
        if path == "/bucket/redirect":
            self.reply(307, headers={"Location": "http://127.0.0.1:" + str(self.server.server_port) + "/leak"})
            return
        if path == "/bucket/slow":
            time.sleep(1)
            try:
                self.reply(200, "delayed")
            except (BrokenPipeError, ConnectionResetError):
                pass
            return
        if path == "/bucket/huge":
            self.reply(200, b"x" * 4096)
            return
        if path == "/bucket/missing":
            self.reply(404, "<Error><Code>NoSuchKey</Code><Message>" + SECRET + "</Message></Error>")
            return
        if path == "/bucket/echo":
            self.reply(403, "<Error><Code>" + ACCESS + "</Code><Message>" + SECRET + "</Message></Error>")
            return
        if "list-type" in query:
            assert query["list-type"] == "2" and query["encoding-type"] == "url"
            prefix = query.get("prefix", "")
            if prefix == "malformed":
                self.reply(200, "<ListBucketResult><IsTruncated>false</IsTruncated><IsTruncated>true</IsTruncated></ListBucketResult>")
                return
            if prefix == "dtd":
                self.reply(200, '<!DOCTYPE x [<!ENTITY p SYSTEM "file:///etc/passwd">]><ListBucketResult>&p;</ListBucketResult>')
                return
            if prefix == "overflow":
                self.reply(200, "<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>x</Key><Size>18446744073709551616</Size></Contents></ListBucketResult>")
                return
            token = query.get("continuation-token")
            if prefix == "cycle":
                next_token = "A" if token != "A" else "B"
                self.reply(200, "<ListBucketResult><IsTruncated>true</IsTruncated><NextContinuationToken>" + next_token + "</NextContinuationToken></ListBucketResult>")
                return
            if token is None or prefix == "repeat":
                text = '<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><EncodingType>url</EncodingType><IsTruncated>true</IsTruncated><NextContinuationToken>next+/=&amp; token</NextContinuationToken><Contents><Key>dir%2F%E9%9B%AA%20%2B%25.txt</Key><Size>9</Size><ETag>&quot;abc&quot;</ETag><LastModified>2026-01-02T03:04:05Z</LastModified></Contents><CommonPrefixes><Prefix>dir%2F</Prefix></CommonPrefixes></ListBucketResult>'
            else:
                assert token == "next+/=& token"
                text = "<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>second</Key><Size>0</Size></Contents></ListBucketResult>"
            self.reply(200, text)
            return
        if "uploads" in query:
            upload_id = "upload+/=&" + str(len(Fixture.uploads) + Fixture.aborted + 1)
            Fixture.uploads[upload_id] = {"path": path, "parts": {}}
            self.reply(200, "<InitiateMultipartUploadResult><UploadId>" + upload_id.replace("&", "&amp;") + "</UploadId></InitiateMultipartUploadResult>")
            return
        if "uploadId" in query:
            upload = Fixture.uploads[query["uploadId"]]
            assert upload["path"] == path
            if self.command == "DELETE":
                if path == "/bucket/abortfail":
                    self.reply(500, "<Error><Code>InternalError</Code></Error>")
                    return
                Fixture.aborted += 1
                del Fixture.uploads[query["uploadId"]]
                self.reply(204)
                return
            if self.command == "PUT":
                if path in ("/bucket/failpart", "/bucket/abortfail"):
                    self.reply(500, "<Error><Code>InternalError</Code></Error>")
                    return
                number = int(query["partNumber"])
                etag = '"part-' + str(number) + '"'
                upload["parts"][number] = (etag, body)
                self.reply(200, headers={"ETag": etag})
                return
            if path == "/bucket/failcomplete":
                self.reply(200, "\n <Error><Code>InternalError</Code></Error>")
                return
            root = ET.fromstring(body)
            assert root.tag == "CompleteMultipartUpload"
            data = b""
            numbers = []
            for part in root:
                number = int(part.findtext("PartNumber"))
                etag, content = upload["parts"][number]
                assert part.findtext("ETag") == etag
                numbers.append(number)
                data += content
            assert numbers == sorted(set(numbers))
            Fixture.objects[path] = data
            del Fixture.uploads[query["uploadId"]]
            self.reply(200, '<CompleteMultipartUploadResult><ETag>"complete"</ETag></CompleteMultipartUploadResult>')
            return
        if self.command == "PUT":
            Fixture.objects[path] = body
            self.reply(200, headers={"ETag": '"stored"'})
        elif self.command == "DELETE":
            Fixture.objects.pop(path, None)
            self.reply(204)
        elif path in Fixture.objects:
            self.reply(200, Fixture.objects[path], {"ETag": '"stored"', "Content-Type": "application/octet-stream", "x-amz-version-id": "v1"})
        else:
            self.reply(404, "<Error><Code>NoSuchKey</Code></Error>")

    do_GET = dispatch
    do_HEAD = dispatch
    do_PUT = dispatch
    do_POST = dispatch
    do_DELETE = dispatch


server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
server.daemon_threads = True
with open(sys.argv[1] + ".tmp", "w") as output:
    output.write("http://127.0.0.1:" + str(server.server_port))
os.replace(sys.argv[1] + ".tmp", sys.argv[1])
server.serve_forever()
