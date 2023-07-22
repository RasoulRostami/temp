from urllib.parse import urlparse, urlunparse


def remove_extra_slashes(url):
    parsed_url = urlparse(url)
    new_path = "/".join(segment for segment in parsed_url.path.split("/") if segment)
    new_query = "/".join(segment for segment in parsed_url.query.split("/") if segment)
    if new_query:
        new_path += "/"
    return urlunparse(parsed_url._replace(path=new_path, query=new_query))


print(remove_extra_slashes("http://google.com//page////number/?name=tom/"))
# print(remove_extra_slashes("http:////google.com/////new//page/number/////1/"))
# print(remove_extra_slashes("https://google.com/new//page/number/1/////"))
# print(remove_extra_slashes("https://google.com/new//page/number/////1/?new=query/"))
