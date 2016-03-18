-module('lager_elogfmt_formatter').

%% API exports
-export([format/2,
         format/3
        ]).

-type default_entry() :: {string(), string()}.
-type mfa_entry() :: {string(), mfa()}.
-type config() :: [{app, string()} |
                   {defaults, [default_entry()]} |
                   {mfa, mfa_entry()}
                  ].

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
    MFAs = [transform(Key, apply(M, F, A))
            || {mfa, {Key, {M, F, A}}} <- proplists:lookup_all(mfa, Config)],
    Props = filter_undefined([{"app", App},
                              severity(Msg),
                              msg(Msg) |
                              Defaults ++
                              MFAs ++
                              meta(Msg, App)
                             ]),
    elogfmt_core:logmessage(Props) ++ "\n".

%%====================================================================
%% Internal functions
%%====================================================================

severity(Msg) ->
    Severity = lager_msg:severity(Msg),
    {"severity", atom_to_list(Severity)}.

msg(Msg) ->
    Message = escape(lager_msg:message(Msg)),
    {"msg", ["\"", Message, "\""]}.

meta(Msg, App) ->
    Meta = lager_msg:metadata(Msg),
    transform_meta(Meta, App, []).

transform_meta([], _App, Acc) ->
    Acc;
transform_meta([{pid, _Pid} | Rest], App, Acc) ->
    %% ignore pid
    transform_meta(Rest, App, Acc);
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
    transform_meta(Rest, App, [{MetricKey, Value},
                               {splunk_key(Key), Value} | Acc]);
transform_meta([{{measure, Key}, Value} | Rest], App, Acc) ->
    MetricKey = ["measure#", App, ".", Key],
    transform_meta(Rest, App, [{MetricKey, Value},
                               {splunk_key(Key), Value} | Acc]);
transform_meta([{{sample, Key}, Value} | Rest], App, Acc) ->
    MetricKey = ["sample#", App, ".", Key],
    transform_meta(Rest, App, [{MetricKey, Value},
                               {splunk_key(Key), Value} | Acc]);
transform_meta([{{unique, Key}, Value} | Rest], App, Acc) ->
    MetricKey = ["unique#", App, ".", Key],
    transform_meta(Rest, App, [{MetricKey, Value},
                               {splunk_key(Key), Value} | Acc]);
transform_meta([{_Key, undefined} | Rest], App, Acc) ->
    %% filter undefined values
    transform_meta(Rest, App, Acc);
transform_meta([{Key, Value} | Rest], App, Acc) ->
    Transformed = transform(Key, Value),
    transform_meta(Rest, App, [Transformed | Acc]).

transform(Key, Value) when is_atom(Value) ->
    {splunk_key(Key), atom_to_list(Value)};
transform(Key, Value) when is_binary(Value) ->
    transform(Key, binary_to_list(Value));
transform(Key, Value) when is_list(Value) ->
    EscapedValue = ["\"", escape(Value), "\""],
    {splunk_key(Key), EscapedValue};
transform(Key, Value) ->
    {splunk_key(Key), Value}.

splunk_key(Key) when is_atom(Key) ->
    splunk_key(atom_to_list(Key));
splunk_key(Key) ->
    re:replace(Key, "-", "_", [global, {return, list}]).

filter_undefined(Props) ->
    [{K, V} || {K, V} <- Props, V =/= undefined].

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

msg_test() ->
    Msg = lager_msg:new("\n\t\b\r'\"\\", error, [], []),
    ?assertEqual({"msg",
                  ["\"", ["\\n","\\t","\\b","\\r","\\'","\\\"","\\\\"], "\""]},
                 msg(Msg)).

msg_iolist_test() ->
    Msg = lager_msg:new(["\"", ["\n\t"],[["\b"]],"\r'\"\\"], error, [], []),
    ?assertEqual({"msg",
                  ["\"", ["\\\"","\\n","\\t","\\b","\\r","\\'","\\\"","\\\\"],
                   "\""]},
                 msg(Msg)).

meta_ignore_pid_test() ->
    Msg = lager_msg:new("msg", error, [{pid, list_to_pid("<0.1.0>")}], []),
    ?assertEqual([], meta(Msg, "myapp")).

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
    ?assertEqual([{["count#", "myapp", ".", "my_count"], 42},
                  {"my_count", 42}],
                 meta(Msg, "myapp")).

meta_measure_test() ->
    Msg = lager_msg:new("msg", error, [{{measure, "my_measure"}, 23}], []),
    ?assertEqual([{["measure#", "myapp", ".", "my_measure"], 23},
                  {"my_measure", 23}],
                 meta(Msg, "myapp")).

meta_sample_test() ->
    Msg = lager_msg:new("msg", error, [{{sample, "my_sample"}, 1}], []),
    ?assertEqual([{["sample#", "myapp", ".", "my_sample"], 1},
                  {"my_sample", 1}],
                 meta(Msg, "myapp")).

meta_unique_test() ->
    Msg = lager_msg:new("msg", error, [{{unique, "my_unique"}, 1234}], []),
    ?assertEqual([{["unique#", "myapp", ".", "my_unique"], 1234},
                  {"my_unique", 1234}],
                 meta(Msg, "myapp")).

generic_meta_atom_value_test() ->
    Msg = lager_msg:new("msg", error, [{key, value}], []),
    ?assertEqual([{"key", "value"}], meta(Msg, "myapp")).

generic_meta_dashed_key_test() ->
    Msg = lager_msg:new("msg", error, [{"k-e-y", "value"}], []),
    ?assertEqual([{"k_e_y", ["\"","value","\""]}], meta(Msg, "myapp")).

format_test() ->
    Msg = lager_msg:new("'msg'", error, [{application, myapp},
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
    Config = [{app, "myapp"},
              {defaults, [{"default", "value"}]},
              {mfa, {"rand", {rand, uniform, [1]}}}
             ],
    ?assertEqual(<<"app=myapp "
                   "severity=error "
                   "msg=\"\\'msg\\'\" "
                   "default=value "
                   "rand=1 "
                   "dashed_key=\"value\" "
                   "string=\"\\'test\\'\\n\" "
                   "binary=\"binary\" "
                   "atom=value "
                   "sample#myapp.mysample=42 "
                   "mysample=42 "
                   "unique#myapp.myunique=1234 "
                   "myunique=1234 "
                   "measure#myapp.mymeasure=23 "
                   "mymeasure=23 "
                   "count#myapp.mycount=1 "
                   "mycount=1 "
                   "line=100 "
                   "function=myfun "
                   "module=mymod "
                   "application=myapp"
                   "\n">>,
                 list_to_binary(format(Msg, Config))).

-endif.
