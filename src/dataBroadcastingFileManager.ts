interface dataBroadCastingFileManager {
    readFile(componentTag: string, moduleName: string, resourceName: string): Uint8Array;
    getModule(componentTag: string, moduleName: string): Uint8Array;
    saveFile(componentTag: string, moduleName: string, resourceName: string, data: Uint8Array): boolean;
}