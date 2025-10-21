POLICIES = [
    {
        "name": "Block confidential keywords",
        "check": lambda sender, recipient, content: not any(
            word in content.lower() for word in ["confidential", "secret", "classified"]
        ),
        "message": "Blocked: Content contains restricted keywords."
    },
    {
        "name": "Block external emails with attachments",
        "check": lambda sender, recipient, content: not (
            recipient.endswith("external.com") and "[attachment]" in content
        ),
        "message": "Blocked: External recipients cannot receive attachments."
    }
]
