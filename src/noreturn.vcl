# vcl_* subs are reserved, so wrap vcl_builtin_recv
sub noreturn_builtin_recv {
	call vcl_builtin_recv;
}

sub vcl_init {
noreturn.internal_set_builtin_recv(noreturn_builtin_recv);
}

sub vcl_synth {
	noreturn.internal_proceed();
}

sub vcl_backend_fetch {
	noreturn.internal_load_state(bereq.http.action);
	unset bereq.http.action;
	return(fetch);
}

sub vcl_backend_response {
	noreturn.internal_proceed();
}

sub vcl_backend_error {
	noreturn.internal_proceed();
}
