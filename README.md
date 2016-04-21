# lager_elogfmt_formatter

A lager formatter for `logfmt` and `structured logs`.

Leverages [lager](https://github.com/lager/lager.git) metadata to simplify
logging of messages consumed, for example, by Splunk and Librato.

Additional metadata passed to logging calls with lager (when using the lager
parse transform) will be included in logs:

```
lager:error([{type, badarg}, {{count, "badarg"}, 1}], "msg='failed to parse: ~w'", [Input])
```

The output to this log call will include:

```
app=myapp application=my_api module=parser function=parse line=42 severity=error type=badarg count#myapp.badarg=1 msg='failed to parse: ...'
```

# Setup & Configuration

Include `lager_elogfmt_formatter` in your `rebar.config`:

```
{deps, [
    {lager_elogfmt_formatter,
     {git, "https://github.com/heroku/lager_elogfmt_formatter.git", {tag, "1.1.0"}}}
]}
```

Set `lager_elogfmt_formatter` as formatter for a lager handler. There are the
following configurations:

* (Required) `{app, string()}`: Defines an `app` entry which is included in all
    log messages.
* (Optional) `{defaults, [{string(), string()}]}`: Set other default entries
    which will occurr in all log messages.

A lager configuration example looks like this:

```
{lager, {
    [{handlers, [
        {lager_console_backend, info, {lager_elogfmt_formatter, [{app, "myapp"},
                                                                 {defaults, [{"key", "value"}]}
                                                                ]}
        }]
    }]}
}
```

# Test

Run the unit tests and type checker with:

```
$ rebar3 eunit, dialyzer
```

