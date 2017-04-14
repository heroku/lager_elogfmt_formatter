-module('lager_elogfmt_formatter').

%% API exports
-export([format/2,
         format/3
        ]).

-type default_entry() :: {string(), string()}.
-type config() :: [{app, string()} | {defaults, [default_entry()]}].

%%====================================================================
%% API functions
%%====================================================================

-spec format(lager:msg(), config(), list()) -> elogfmt_core:logmessage().
format(Msg, Config, _Color) ->
    %% this formatter ignores color
    format(Msg, Config).

-spec format(lager:msg(), config()) -> elogfmt_core:logmessage().
format(Msg, Config) ->
    App = proplists:get_value(app, Config),
    Defaults = proplists:get_value(defaults, Config, []),
    StripPid = proplists:get_value(strip_pid, Config, true),
    Meta = meta(Msg, App),
    Props = filter(StripPid, [{"app", App}, severity(Msg) | Defaults ++ Meta]),
    [elogfmt_core:logmessage(Props),  " ", lager_msg:message(Msg), "\n"].

%%====================================================================
%% Internal functions
%%====================================================================

severity(Msg) ->
    Severity = lager_msg:severity(Msg),
    {"severity", atom_to_list(Severity)}.

meta(Msg, App) ->
    Meta = lager_msg:metadata(Msg),
    transform_meta(Meta, App, []).

transform_meta([], _App, Acc) ->
    Acc;
transform_meta([{pid, Pid} | Rest], App, Acc) when is_pid(Pid) ->
    transform_meta([{pid, pid_to_list(Pid)} | Rest], App, Acc);
transform_meta([{pid, Pid} | Rest], App, Acc) ->
    transform_meta(Rest, App, [{"pid", Pid} | Acc]);
transform_meta([{node, Node} | Rest], App, Acc) ->
    transform_meta(Rest, App, [{"node", atom_to_list(Node)} | Acc]);
transform_meta([{application, Application} | Rest], App, Acc) ->
    transform_meta(Rest, App,
                   [{"application", atom_to_list(Application)} | Acc]);
transform_meta([{module, Mod} | Rest], App, Acc) ->
    transform_meta(Rest, App, [{"module", atom_to_list(Mod)} | Acc]);
transform_meta([{function, Fun} | Rest], App, Acc) ->
    transform_meta(Rest, App, [{"function", atom_to_list(Fun)} | Acc]);
transform_meta([{{count, Key}, Value} | Rest], App, Acc) ->
    MetricKey = ["count#", App, ".", Key],
    transform_meta(Rest, App, [{MetricKey, Value} | Acc]);
transform_meta([{{measure, Key}, Value} | Rest], App, Acc) ->
    MetricKey = ["measure#", App, ".", Key],
    transform_meta(Rest, App, [{MetricKey, Value} | Acc]);
transform_meta([{{sample, Key}, Value} | Rest], App, Acc) ->
    MetricKey = ["sample#", App, ".", Key],
    transform_meta(Rest, App, [{MetricKey, Value} | Acc]);
transform_meta([{{unique, Key}, Value} | Rest], App, Acc) ->
    MetricKey = ["unique#", App, ".", Key],
    transform_meta(Rest, App, [{MetricKey, Value} | Acc]);
transform_meta([{_Key, undefined} | Rest], App, Acc) ->
    %% filter undefined values
    transform_meta(Rest, App, Acc);
transform_meta([{Key, Value} | Rest], App, Acc) when is_atom(Value) ->
    transform_meta(Rest, App, [{splunk_key(Key), atom_to_list(Value)} | Acc]);
transform_meta([{Key, Value} | Rest], App, Acc) when is_binary(Value) ->
    transform_meta([{Key, binary_to_list(Value)} | Rest], App, Acc);
transform_meta([{Key, Value} | Rest], App, Acc) when is_list(Value) ->
    EscapedValue = ["\"", escape(Value), "\""],
    transform_meta(Rest, App, [{splunk_key(Key), EscapedValue} | Acc]);
transform_meta([{Key, Value} | Rest], App, Acc) ->
    transform_meta(Rest, App, [{splunk_key(Key), Value} | Acc]).

splunk_key(Key) when is_atom(Key) ->
    splunk_key(atom_to_list(Key));
splunk_key(Key) ->
    re:replace(Key, "-", "_", [global, {return, list}]).

filter(StripPid, Props) ->
    [{K, V} || {K, V} <- Props, V =/= undefined,
               not StripPid orelse K =/= "pid"].

escape(Msg) ->
    FlatMsg = lists:flatten(Msg),
    lists:foldr(fun(C, Acc) -> [escape_char(C) | Acc] end, [], FlatMsg).

escape_char($\n) -> "\\n";
escape_char($\t) -> "\\t";
escape_char($\b) -> "\\b";
escape_char($\r) -> "\\r";
escape_char($')  -> "\\'";
escape_char($")  -> "\\\"";
escape_char($\\) -> "\\\\";
escape_char(C)   -> C.

%%====================================================================
%% tests
%%====================================================================
-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

severity_test() ->
    Msg = lager_msg:new("msg", error, [], []),
    ?assertEqual({"severity", "error"}, severity(Msg)).

escape_test() ->
    Msg = lager_msg:new("", error, [{test, "\n\t\b\r'\"\\"}], []),
    ?assertEqual([{"test",
                  ["\"", ["\\n","\\t","\\b","\\r","\\'","\\\"","\\\\"], "\""]}],
                 meta(Msg, "myapp")).

meta_node_test() ->
    Msg = lager_msg:new("msg", error, [{node, node()}], []),
    ?assertEqual([{"node", atom_to_list(node())}], meta(Msg, "myapp")).

meta_application_test() ->
    Msg = lager_msg:new("msg", error, [{application, myapp}], []),
    ?assertEqual([{"application", "myapp"}], meta(Msg, "myapp")).

meta_module_test() ->
    Msg = lager_msg:new("msg", error, [{module, mymod}], []),
    ?assertEqual([{"module", "mymod"}], meta(Msg, "myapp")).

meta_function_test() ->
    Msg = lager_msg:new("msg", error, [{function, myfun}], []),
    ?assertEqual([{"function", "myfun"}], meta(Msg, "myapp")).

meta_count_test() ->
    Msg = lager_msg:new("msg", error, [{{count, "my_count"}, 42}], []),
    ?assertEqual([{["count#", "myapp", ".", "my_count"], 42}],
                 meta(Msg, "myapp")).

meta_measure_test() ->
    Msg = lager_msg:new("msg", error, [{{measure, "my_measure"}, 23}], []),
    ?assertEqual([{["measure#", "myapp", ".", "my_measure"], 23}],
                 meta(Msg, "myapp")).

meta_sample_test() ->
    Msg = lager_msg:new("msg", error, [{{sample, "my_sample"}, 1}], []),
    ?assertEqual([{["sample#", "myapp", ".", "my_sample"], 1}],
                 meta(Msg, "myapp")).

meta_unique_test() ->
    Msg = lager_msg:new("msg", error, [{{unique, "my_unique"}, 1234}], []),
    ?assertEqual([{["unique#", "myapp", ".", "my_unique"], 1234}],
                 meta(Msg, "myapp")).

generic_meta_atom_value_test() ->
    Msg = lager_msg:new("msg", error, [{key, value}], []),
    ?assertEqual([{"key", "value"}], meta(Msg, "myapp")).

generic_meta_dashed_key_test() ->
    Msg = lager_msg:new("msg", error, [{"k-e-y", "value"}], []),
    ?assertEqual([{"k_e_y", ["\"","value","\""]}], meta(Msg, "myapp")).

format_ignore_pid_test() ->
    Config = [{app, "myapp"}, {strip_pid, true}],
    Msg = lager_msg:new("msg", error, [{pid, list_to_pid("<0.1.0>")}], []),
    ?assertEqual(<<"app=myapp severity=error msg\n">>,
                 iolist_to_binary(format(Msg, Config))).

format_no_ignore_pid_test() ->
    Config = [{app, "myapp"}, {strip_pid, false}],
    Msg = lager_msg:new("msg", error, [{pid, list_to_pid("<0.1.0>")}], []),
    ?assertEqual(<<"app=myapp severity=error pid=<0.1.0> msg\n">>,
                 iolist_to_binary(format(Msg, Config))).

format_no_ignore_string_pid_test() ->
    Config = [{app, "myapp"}, {strip_pid, false}],
    Msg = lager_msg:new("msg", error, [{pid, "<0.1.0>"}], []),
    ?assertEqual(<<"app=myapp severity=error pid=<0.1.0> msg\n">>,
                 iolist_to_binary(format(Msg, Config))).

format_test() ->
    Msg = lager_msg:new("msg='msg'", error, [{application, myapp},
                                         {module, mymod},
                                         {function, myfun},
                                         {line, 100},
                                         {{count, "mycount"}, 1},
                                         {{measure, "mymeasure"}, 23},
                                         {{unique, "myunique"}, 1234},
                                         {{sample, "mysample"}, 42},
                                         {atom, value},
                                         {binary, <<"binary">>},
                                         {string, "'test'\n"},
                                         {"dashed-key", "value"},
                                         {undefined_key, undefined}],
                        []),
    Config = [{app, "myapp"}, {defaults, [{"default", "value"}]}],
    ?assertEqual(<<"app=myapp "
                   "severity=error "
                   "default=value "
                   "dashed_key=\"value\" "
                   "string=\"\\'test\\'\\n\" "
                   "binary=\"binary\" "
                   "atom=value "
                   "sample#myapp.mysample=42 "
                   "unique#myapp.myunique=1234 "
                   "measure#myapp.mymeasure=23 "
                   "count#myapp.mycount=1 "
                   "line=100 "
                   "function=myfun "
                   "module=mymod "
                   "application=myapp "
                   "msg='msg'"
                   "\n">>,
                 list_to_binary(format(Msg, Config))).

-endif.
