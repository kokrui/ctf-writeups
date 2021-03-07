## Easy SQL (Assigned Writeup)
>This challenge server can be accessed here:
>
>ctf-85ib.balancedcompo.site:9000

### TL;DR
* Webpage vulnerable to SQL injection - however, it has filters for SQL-specific keywords. Notably, SELECT and “.” cannot be used
* SQLmap + Error Messages indicates that the backend server is MySQL
* Stacked SQL injection is possible - can list tables with ``SHOW TABLES;``, then query data with ``HANDLER`` to get flag

### Writeup
_Note: No screenshots because I didn’t take any during the CTF, and the challenge site is now down :(. Also, apparently there was a public write-up of this challenge online with the exact same solution, but we didn’t find/know of it during the CTF so we solved it "legit"_

An initial look at the page shows a text input box, a submit button, and a prefilled query `1`. Submitting `1` reveals the following output, which implies that this is some “search” page. The structured nature of the data implies that a **relational database** is likely on the backend.

Trying an input like ``"; --`` outputs an SQL error message, which not only confirms that it’s SQL, but also implies that the site is simply executing whatever input we submit as an SQL statement. The error message being returned to us also opens up the possibility of a Bool-based Blind SQL Injection, if needed.

Trying `` ';--`` (single quotes) doesn’t show an error, implying that the original query was something like ``SELECT a,b FROM sometable WHERE somecolumn = '<input>';`` We can try sending input ``1' or 1=1; --`` to confirm this, and sure enough we get all the entries of the current table (though they seem to be meaningless).

The page source includes a comment stating that _"SQLmap is not a panacea"_ - meaning that SQLmap won’t be a cure-all solution for this challenge. But it still might be a cure-some, so we run SQLmap, injecting into the GET parameter “inject”:

```bash
root@kali:~$ sqlmap -u ctf-85ib.balancedcompo.site:9000/?inject=1
...
...
DB Version: MySQL 5.0+
```
