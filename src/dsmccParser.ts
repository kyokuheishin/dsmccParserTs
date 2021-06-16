import { Module } from 'module';
import { DlData } from './downloadData';

enum ModuleInfoDescriptor {
    Type = 0x01,
    Name,
    Info,
    Module_link,
    CRC32,
    DownloadTime = 0x07,
    CashPrioriy = 0x71,
    Expire = 0xc0,
    ActivationTime,
    CompressionType,
    Control,
    ProviderPrivate,
    StoreRoot,
    SubDirectory,
    Title,
    DataEncoding,
    TsWithTimestamp,
    RootCert,
    Encrypt,
    ACG,
}

enum PrivateDataDescriptor {
    Info = 0x03,
    DownloadTime = 0x07,
    Expire = 0xc0,
    ActivationTime,
    ProviderPrivate,
    StoreRoot,
    SubDirectory,
    Title,
    RootCert,
    Encrypt,
    ACG,
}

class dsmccParser {
    data: Uint8Array;
    moduleMap = new Map();
    moduleByteMap = new Map();
    privateData = new Uint8Array();

    constructor(data: Uint8Array) {
        this.data = data;
    }

    ProcessDsmccAdaptationHeader(
        data: Uint8Array,
        adaptationLength: number
    ): void {
        let adaptationType = data[0];
        for (let i = 0; i < adaptationLength - 1; i++) {
            console.log(data[1 + i]);
        }
    }

    ProcessDsmccMessageHeader(data: Uint8Array) {
        let protocolDiscriminator = data[0];
        let dsmccType = data[1];
        let messageId = (data[2] << 8) | data[3];
        let transaction_id =
            (data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7]; // 32 Bits
        let reserved = data[8];
        let adaptationLength = data[9];
        let messageLength = (data[10] << 8) | data[11];

        if (adaptationLength > 0) {
            this.ProcessDsmccAdaptationHeader(data.subarray(12), adaptationLength);
        }

        let transaction_no = transaction_id & 0b111111111111111111111111111111;

        return [
            12 + adaptationLength,
            transaction_id,
            transaction_no,
            adaptationLength,
            messageLength,
        ];
    }

    ProcessDescriptor(data: Uint8Array): void {
        let descriptor_tag = data[0];
        let descriptor_length = data[1];

        var resObj:any;
        resObj.offset = descriptor_length;

        switch (descriptor_tag) {
            case ModuleInfoDescriptor.Type: {
                let text_char = new Uint8Array(data, 2, descriptor_length);
                resObj.Type.text_char = text_char;

                break;
            }
            case ModuleInfoDescriptor.Info: {
                let ISO_639_language_code = (data[2] << 16) | (data[3] << 8) | data[4];
                let text_char = new Uint8Array(data, 4, descriptor_length);
                resObj.Info.ISO_639_language_code = ISO_639_language_code;
                resObj.Info.text_char = text_char;
                break;
            }
            case ModuleInfoDescriptor.Name: {
                let text_char = new Uint8Array(data, 2, descriptor_length);
                resObj.Name.text_char = text_char;
                break;
            }
            case ModuleInfoDescriptor.Module_link: {
                let position = data[2];
                let moduleId = (data[3] << 8) | data[4];
                resObj.Module_link.position = position;
                resObj.Module_link.moduleId = moduleId;
                break;
            }
            case ModuleInfoDescriptor.CRC32: {
                let CRC_32 =
                    (data[2] << 24) | (data[3] << 16) | (data[4] << 8) | data[5];
                resObj.CRC32.CRC_32 = CRC_32;
                break;
            }
            case ModuleInfoDescriptor.DownloadTime: {
                let est_download_time =
                    (data[2] << 24) | (data[3] << 16) | (data[4] << 8) | data[5];
                resObj.
                break;
            }
            case ModuleInfoDescriptor.Expire: {
                let time_mode = data[2];

                switch (time_mode) {
                    case 0x01:
                        let MJD_JST_time =
                            (data[3] << 32) |
                            (data[4] << 24) |
                            (data[5] << 16) |
                            (data[6] << 8) |
                            data[7];
                        break;
                    case 0x04:
                        let reserved_future_use = data[3];
                        let passed_seconds =
                            (data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7];
                    default:
                        break;
                }
            }
            case ModuleInfoDescriptor.ActivationTime: {
                let time_mode = data[2];
                switch (time_mode) {
                    case 0x01:
                    case 0x05:
                        let MJD_JST_time =
                            (data[3] << 32) |
                            (data[4] << 24) |
                            (data[5] << 16) |
                            (data[6] << 8) |
                            data[7];
                        break;
                    case 0x02: {
                        let reserved_future_use = (data[3] >> 1) & 0b1111111;
                        let NPT_time =
                            ((data[3] & 0b1) << 32) |
                            (data[4] << 24) |
                            (data[5] << 16) |
                            (data[6] << 8) |
                            data[7];
                        break;
                    }
                    case 0x03:
                        let reserved_future_use = (data[3] >> 4) & 0b1111;
                        let eventRelativeTime =
                            ((data[3] & 0b1111) << 32) |
                            (data[4] << 24) |
                            (data[5] << 16) |
                            (data[6] << 8) |
                            data[7];
                        break;

                    default:
                        break;
                }
            }

            case ModuleInfoDescriptor.CompressionType: {
                let compression_type = data[2];
                let original_size =
                    (data[3] << 24) | (data[4] << 16) | (data[5] << 18) | data[6];
                break;
            }

            case ModuleInfoDescriptor.Control: {
                let control_data_byte = new Uint8Array(data, 2, descriptor_length);
                break;
            }

            case ModuleInfoDescriptor.ProviderPrivate: {
                let private_scope_type = data[2];
                let scope_identifier =
                    (data[3] << 24) | (data[4] << 16) | (data[5] << 18) | data[6];
                let private_byte = new Uint8Array(data, 7, descriptor_length);
                break;
            }

            case ModuleInfoDescriptor.StoreRoot: {
                let update_type = data[2] & 0b1;
                let reserved = (data[2] >> 1) & 0b1111111;
                let store_root_path = new Uint8Array(data, 3, descriptor_length);
                break;
            }

            case ModuleInfoDescriptor.SubDirectory: {
                let subdirectory_path = new Uint8Array(data, 3, descriptor_length);
                break;
            }

            case ModuleInfoDescriptor.Title: {
                let ISO_639_language_code =
                    (data[2] << 24) | (data[3] << 16) | (data[4] << 8) | data[5];
                break;
            }

            case ModuleInfoDescriptor.DataEncoding: {
                let data_compoent_id = (data[2] << 8) | data[3];
                let additional_data_encoding_info = new Uint8Array(
                    data,
                    4,
                    descriptor_length
                );
                break;
            }

            case ModuleInfoDescriptor.RootCert: {
                let root_certificate_type = data[2] & 0b1;
                let reserved = (data[2] >> 1) & 0b1111111;

                if (root_certificate_type == 0) {
                }
            }

            default:
                break;
        }
    }

    ProcessDii(
        data: Uint8Array,
        serviceId: number,
        componentTag: number
    ): number {
        let ProcessDsmccMessageHeaderReturnValues =
            this.ProcessDsmccMessageHeader(data);
        let dsmccMessageHeaderOffset = ProcessDsmccMessageHeaderReturnValues[0];
        let transaction_id = ProcessDsmccMessageHeaderReturnValues[1];
        let transaction_no = ProcessDsmccMessageHeaderReturnValues[2];
        let adaptationLength = ProcessDsmccMessageHeaderReturnValues[3];
        let messageLength = ProcessDsmccMessageHeaderReturnValues[4];
        data = new Uint8Array(data, dsmccMessageHeaderOffset);
        let downloadId =
            (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
        let data_event_id = (downloadId >> 28) & 0b1111;
        let blockSize = (data[4] << 8) | data[5];
        let windowSize = data[6];
        let ackPeriod = data[7];
        let tCDownloadWindow =
            (data[8] << 24) | (data[9] << 16) | (data[10] << 8) | data[11];
        let tCDownloadScenario =
            (data[12] << 24) | (data[13] << 16) | (data[14] << 8) | data[15];

        let descType = data[16];
        let descLen = data[17]; // empty compatibilityDescriptor()
        let numberOfModules = (data[18] << 8) | data[19];

        let dlData = new DlData();
        dlData.ServiceId = serviceId;
        dlData.DownloadId = downloadId;
        dlData.BlockSize = blockSize;
        dlData.WindowSize = windowSize;
        dlData.AckPriod = ackPeriod;
        dlData.TcDownloadWindow = tCDownloadWindow;
        dlData.TcDownloadScenario = tCDownloadScenario;
        dlData.NumberOfModules = numberOfModules;
        dlData.ComponentTag = componentTag;
        for (let i = 0; i < numberOfModules; i++) {
            var moduleObj: any = {
                moduleId: (data[20 + descLen + 0] << 8) | data[20 + descLen + 1],
                moduleSize:
                    (data[20 + descLen + 2] << 24) |
                    (data[20 + descLen + 3] << 16) |
                    (data[20 + descLen + 4] << 8) |
                    data[20 + descLen + 5],
                moduleVersion: data[20 + descLen + 6],
                moduleInfoLength: data[20 + descLen + 7],
            };

            var moduleInfoByte = new Uint8Array(moduleObj.moduleInfoLength);
            for (let j = 0; j < moduleObj.moduleInfoLength;) {
                // moduleInfoByte[j] = data[28 + j];
                this.ProcessDescriptor(new Uint8Array(data, 28 + j))

            }

            this.moduleMap.set(moduleObj.moduleId, moduleObj);
            this.moduleByteMap.set(moduleObj.moduleId, moduleInfoByte);
        }

        let privateDataLength =
            ((data[27 + numberOfModules] & 0b1111) << 12) |
            (data[28 + numberOfModules] << 4) |
            ((data[29 + numberOfModules] >> 4) & 0b1111);

        let privateData = new Uint8Array(privateDataLength);

        for (let i = 0; i < privateDataLength; i++) {
            privateData[i] =
                (data[29 + numberOfModules + i] & 0b1111) |
                ((data[30 + numberOfModules + i] >> 4) & 0b1111);
        }

        return 30 + numberOfModules + privateDataLength; // offset
    }

    ProcessDsmccDownloadDataHeader(data: Uint8Array): number {
        let protocolDiscriminator = data[0];
        let dsmccType = data[1];
        let messageId = (data[2] << 8) | data[3];
        let downloadId =
            (data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7];
        let reserved = data[8];
        let adaptationLength = data[9];
        let messageLength = (data[10] << 8) | data[11];
        if (adaptationLength > 0) {
            this.ProcessDsmccAdaptationHeader(data.subarray(12), adaptationLength);
        }

        return 12 + adaptationLength;
    }

    ProcessDDB(data: Uint8Array): void {
        let offset = this.ProcessDsmccDownloadDataHeader(data);
        data = new Uint8Array(data, offset);
        let moduleId = (data[0] << 8) | data[1];
        let moduleVersion = data[2];
        let reserved = data[3];
    }

    ProcessDsmccSection(data: Uint8Array): void {
        let table_id = data[0];
        let section_syntax_indicator = (data[1] >> 7) & 0b1;
        let private_indicator = (data[1] >> 6) & 0b1;
        let reserved1 = (data[1] >> 5) & 0b11;
        let dsmcc_section_length = (data[1] & (0b1111 << 8)) | data[2];
        let table_id_extension = (data[3] << 8) | data[4];
        let reserved2 = (data[5] >> 6) & 0b11;
        let version_number = (data[5] >> 3) & 0b11111;
        let current_next_indicator = (data[5] >> 7) & 0b1;
        let section_number = data[6];
        let last_section_number = data[7];

        switch (table_id) {
            case 0x3b:
                // this.ProcessDii(data.subarray(8));
                break;
            case 0x3c:
                break;
            case 0x3e:
                break;
            default:
                break;
        }
    }
}
