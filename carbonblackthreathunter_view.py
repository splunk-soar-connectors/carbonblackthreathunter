
def get_ctx_result(provides, result):
    """ Function that parses data.

    :param result: result
    :param provides: action name
    :return: response data
    """

    ctx_result = {}

    param = result.get_param()
    summary = result.get_summary()
    data = result.get_data()

    ctx_result['param'] = param

    if summary:
        ctx_result['summary'] = summary
    ctx_result['action'] = provides
    if not data:
        ctx_result['data'] = {}
        return ctx_result

    ctx_result['data'] = data

    return ctx_result


def display_view(provides, all_app_runs, context):
    """ Function that displays view.

    :param provides: action name
    :param context: context
    :param all_app_runs: all app runs
    :return: html page
    """

    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:

            ctx_result = get_ctx_result(provides, result)
            if not ctx_result:
                continue
            results.append(ctx_result)

    if provides == "get feed reports":
       return_page = "carbonblackthreathunter_get_feed_reports.html"
    if provides == "delete report ioc":
       return_page = "carbonblackthreathunter_delete_report_ioc.html"
    if provides == "create report ioc":
       return_page = "carbonblackthreathunter_create_report_ioc.html"
    if provides == "delete ioc value":
       return_page = "carbonblackthreathunter_delete_ioc_value.html"

    return return_page
