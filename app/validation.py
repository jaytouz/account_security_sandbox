import re

from fastapi import HTTPException

_EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,190}\.[A-Za-z]{2,24}$")


def normalise_email(value: str) -> str:
    email = (value or "").strip().lower()
    if not _EMAIL.match(email):
        raise HTTPException(status_code=422, detail={"code": "bad_email", "message": "Not a valid email."})
    return email
