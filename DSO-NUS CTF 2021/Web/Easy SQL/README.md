# Easy SQL [179 pts] (Assigned Writeup)
>This challenge server can be accessed here:
>
>ctf-85ib.balancedcompo.site:9000

## TL;DR
* Webpage vulnerable to SQL injection - however, it has filters for SQL-specific keywords. Notably, SELECT and “.” cannot be used
* SQLmap + Error Messages indicates that the backend server is MySQL
* Stacked SQL injection is possible - can list tables with ``SHOW TABLES;``, then query data with ``HANDLER`` to get flag

## Writeup
_Note: No screenshots because I didn’t take any during the CTF, and the challenge site is now down :(. Also, apparently there was a public write-up of this challenge online with the exact same solution, but we didn’t find/know of it during the CTF so we solved it "legit"_

---
### Enumeration
An initial look at the page shows a text input box, a submit button, and a prefilled query `1`. Submitting `1` reveals the following output, which implies that this is some “search” page. The structured nature of the data implies that a **relational database** is likely on the backend.

Trying an input like ``"; --`` outputs an SQL error message, which not only confirms that it’s SQL, but also implies that the site is simply executing whatever input we submit as an SQL statement. The error message being returned to us also opens up the possibility of a Bool-based Blind SQL Injection, if needed.

Trying `` ';--`` (single quotes) doesn’t show an error, implying that the original query was something like ``SELECT a,b FROM sometable WHERE somecolumn = '<input>';`` We can try sending input ``1' or 1=1; --`` to confirm this, and sure enough we get all the entries of the current table (though they seem to be meaningless).

The page source includes a comment stating that _"SQLmap is not a panacea"_ - meaning that [SQLmap](https://github.com/sqlmapproject/sqlmap) won’t be a cure-all solution for this challenge. But it still might be a cure-some, so we run SQLmap, injecting into the GET parameter “inject”:

``` console
root@kali:~# sqlmap -u "ctf-85ib.balancedcompo.site:9000/?inject=1"
...
...
DB Version: MySQL 5.0+
```

Thankfully, SQLmap indeed doesn’t seem to be an insta-win for this challenge, though it directly reveals to us that the specific relational database in use is likely MariaDB, a still-super-similar fork of MySQL.

The basic plan of attack for most “easy” SQL Injection challenges like this is as follows, where we assume the flag is in some random table in the database:
* Figure out how many columns there are in the current table in order to use UNION to leak other tables (by bruteforcing ``UNION SELECT 1,2,..,n`` until there is no error)
* Leak a list of all the tables in the database, eg. through ``information_schema.tables``
* Leak a list of all the columns, eg. through ``information_schema.columns``
* Leak the flag with ``UNION SELECT flag_column, required_filler_columns_for_union FROM flag_table``

Alternatively, sometimes we have to leak out SQL Server user information, and maybe crack password hashes and login/do other stuff.

---
### Filter Bypass...? (fail)
However, attempting even the first step reveals that there is a PHP blacklist/filter blocking specific SQL keywords. In this case, our query can’t be executed because of a filter on the SELECT statement. There are a few common ways to try to bypass such a filter:
* URL Encoding specific letters (however, in this case, these are parsed before they are sent to the PHP filter. They are also only parsed once, so double encoding doesn’t work)
* If preg_replace is used (and only once), one can try something like ``SELSELECTECT``, hoping the middle ``SELECT`` is removed by the filter, therefore ending up executing… ``SELECT``. However, in this case, ``preg_match`` is used, which prevents execution if any keyword appears at all

There are 2 other possibilities - firstly, **Unicode Smuggling**, or second, that we simply cannot use this UNION SELECT technique and there is supposed to be another way around this.

Seeing as that there is a **Unicode Chinese full stop (U+3002 IDEOGRAPHIC FULL STOP)** on the page, it appears to be a hint that we’re supposed to do some unicode smuggling - where homoglyphs are used in place of the ASCII character, and the hope is that these are converted to ASCII somewhere in the backend after the filter. I spend hours trying out various variations (greek, cyrillic) of all the letters in SELECT and the other SQL statements filtered - these pass the PHP filter, but unfortunately don’t get converted to their ASCII counterparts by the time they reach the SQL execute statement, and the backend consistently throws syntax errors.

---
### Stacked Injection
Therefore, we take a look at another important observation - normally, SQL Injection challenges require manipulation and abuse of **Data Query Language** - the subset of SQL that exclusively involves retrieving data from relational databases. (examples of DQL statements include SELECT, FROM, WHERE, UNION, etc.). However, the filter includes statements from **Data Manipulation Language (DML) and Data Definition Language (DDL) - statements like INSERT, UPDATE, DELETE, etc.**

DML and DDL are usually only relevant in SQL Injection challenges that involve **Stacked SQL Injections**. A Stacked SQL Injection is when multiple distinct SQL statements (separated by semicolons) are allowed to be injected and executed. Stacked SQL Injections are generally way easier than conventional SQL Injection challenges (eg. involving UNIONs or even Time-based Blind injections) - which explains the challenge title “Easy SQL”.

We can test for a Stacked SQL Injection by inputting

``'; show tables; --``

This provides us with some output revealing that the table name is ``1919810931114514``.

We can then view tables with:

``; show columns from `1919810931114514`; -- ``

We can then see that there is a column ``flag``.

Now, we need to query the data in the column ``flag`` in the table ``1919810931114514``. Conventionally, we would simply run: ``SELECT flag FROM `1919810931114514`; -- ``. However, the ``SELECT`` statement is banned by the filter.

We start looking through MySQL Documentation (assuming that MariaDB ≈≈ MySQL, and because MySQL’s official docs are more comprehensive), going through the docs for every MySQL statement that we’re not familiar with - we come across the ``HANDLER`` statement which looks interesting.

![image](./screenshots/ss1.png)

Hmm… syntax (eg. ``READ``-ing something, followed by ``WHERE/LIMIT``) looks similar to the ``SELECT`` clause...

Sure enough, when we scroll down a bit, we see that there’s a direct comparison to the ``SELECT`` clause!

![image](./screenshots/ss2.png)

We can thus apply the ``HANDLER`` function to read the data in the ``1919810931114514`` table! _(In actual fact, I spent ~20minutes trying to figure out my error before realising I had to ``HANDLER \<table\> OPEN``... derp_

---
### Getting Flag
The **final injection** is therefore:
```
'; HANDLER `1919810931114514` OPEN; HANDLER `1919810931114514` READ FIRST; --
```

The corresponding URL to retrieve the flag (if the site was up) would be: http://ctf-f3jj.balancedcompo.site:9000/?inject=%27;%20HANDLER%20%601919810931114514%60%20OPEN;%20HANDLER%20%601919810931114514%60%20READ%20FIRST;--

## Takeaways
* Always check for all options/types of exploits! Start from easy things then build up to more complex possible solutions/bypasses
* HANDLER is something I’ve never encountered before, so pretty cool!
