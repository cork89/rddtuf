# RddtUF

This projects aims to help to unfurl reddit mobile links to the full link that then can be accessed by the devvit api

i.e.
```https://reddit.com/r/programming/s/NpJwOReNkQ```

would be converted to 

```https://www.reddit.com/r/programming/comments/1ln9nho/test_names_should_be_sentences/```

Quickstart:
1. a sqlite database file should be created in the root dir called reddituf.db
2. cgo enabled
3. a .env file with the appropriate variables
4. a reddit app created on https://www.reddit.com/prefs/apps
5. optionally air reload server and run with ```air``` or just ```go run .```