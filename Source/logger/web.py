from . import bc, filter


def get_message(log_filter: filter.filter_type_web, bcolors: bc.bcolors, text: bytes, is_error: bool, status: int | None = None) -> str | None:
    if not is_error:
        if not log_filter.urls:
            return

        if status is not None:
            if status < 300:
                status_str = f'{bcolors.OKGREEN}{status}{bcolors.ENDC}'
            elif status < 400:
                status_str = f'{bcolors.WARNING}{status}{bcolors.ENDC}'
            else:
                status_str = f'{bcolors.FAIL}{status}{bcolors.ENDC}'
        else:
            status_str = f'{bcolors.WARNING}??{bcolors.ENDC}'

        return (
            f'{bcolors.OKCYAN}[Webserver]{bcolors.ENDC} [%s] %s'
        ) % (
            status_str,
            text.decode('utf-8'),
        )

    if not log_filter.errors:
        return
    return (
        f'{bcolors.FAIL}[Webserver Error]\n%s{bcolors.ENDC}'
    ) % (
        text.decode('utf-8'),
    )