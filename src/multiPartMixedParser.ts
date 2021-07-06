
class ModuleResource {
    ContentType: String = "";
    ContentLocation: String = "";
    ContentLength: Number = 0;
    ContentEncoding: String = "";
    ContentByte: Uint8Array = new Uint8Array();

}

const mimeParser = (raw: Uint8Array) => {
    let rawString: String = new TextDecoder().decode(raw);
    let splitedString = rawString.split("\r\n");
    let trimedSplitedString = splitedString.map(x => x.trim());
    let header = trimedSplitedString[0].split(";");
    let contentType = header[0].split(":")[1];

    let boundary = header[1].split("=")[1].slice(1, -1);
    let delimiter = "--" + boundary;
    let closeDelimiter = delimiter + "--";
    let res = Array<ModuleResource>();


    let moduleResource = new ModuleResource();
    for (let i = 2; i < splitedString.length; i++) {
        const element = splitedString[i];
        if (element == delimiter) {
            res.push(moduleResource);
            moduleResource = new ModuleResource();
            continue
        }

        if (element == closeDelimiter) {
            res.push(moduleResource);
            break;
        }

        if (element == "") {
            continue;
        }

        if (element.includes("Content-Type")) {
            moduleResource.ContentType = element.split(":")[1];
            continue;
        }

        if (element.includes("Content-Location")) {
            moduleResource.ContentLocation = element.split(":")[1];
            continue;
        }

        if (element.includes("Content-Length")) {
            moduleResource.ContentLength = Number(element.split(":")[1]);
            continue;
        }

        moduleResource.ContentByte = new TextEncoder().encode(element);




    }


};