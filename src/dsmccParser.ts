// noinspection ShiftOutOfRangeJS,PointlessArithmeticExpressionJS

import { Module } from 'module';
import { DlData } from './downloadData';
import { RawDeflate, RawInflate } from 'zlibt2/raw';
import { mimeParser } from './multiPartMixedParser';
import { fs } from 'memfs';


enum ModuleInfoDescriptor {
  Type = 0x01,
  Name,
  Info,
  Module_link,
  CRC32,
  DownloadTime = 0x07,
  CashPriority = 0x71,
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
  downloadDataMap = new Map();
  privateData = new Uint8Array();
  networkId: number;
  transportStreamId: number;
  serviceId: number;
  componentTag: number;


  constructor(data: Uint8Array, networkId: number, transportStreamId: number, serviceId: number, componentTag: number) {
    this.data = data;
    this.networkId = networkId;
    this.transportStreamId = transportStreamId;
    this.serviceId = serviceId;
    this.componentTag = componentTag;
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

  ProcessDescriptor(data: Uint8Array, moduleInfoLength: number) {
    let descriptor_tag = data[0];
    let descriptor_length = data[1];

    var resObj: any;
    let offset = descriptor_length + 2;

    switch (descriptor_tag) {
      case ModuleInfoDescriptor.Type: {
        let text_char = new Uint8Array(data, 2, descriptor_length);
        resObj.Type = new TextDecoder().decode(text_char);

        break;
      }
      case ModuleInfoDescriptor.Info: {
        let ISO_639_language_code = (data[2] << 16) | (data[3] << 8) | data[4];
        let text_char = new Uint8Array(data, 5, descriptor_length - 1);
        resObj.Info.ISO_639_language_code = ISO_639_language_code;
        resObj.Info.text_char = text_char;
        break;
      }
      case ModuleInfoDescriptor.Name: {
        let text_char = new Uint8Array(data, 2, descriptor_length);

        resObj.Name = new TextDecoder().decode(text_char);
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
        resObj.CRC32 = CRC_32;
        break;
      }
      case ModuleInfoDescriptor.DownloadTime: {
        let est_download_time =
          (data[2] << 24) | (data[3] << 16) | (data[4] << 8) | data[5];
        resObj.DownloadTime.est_download_time = est_download_time;
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
            resObj.Expire.MJD_JST_time = MJD_JST_time;
            break;
          case 0x04:
            let reserved_future_use = data[3];
            let passed_seconds =
              (data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7];
            resObj.reserved_future_use = reserved_future_use;
            resObj.passed_seconds = passed_seconds;
            break;
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
            resObj.ActivationTime.MJD_JST_time = MJD_JST_time;
            break;
          case 0x02: {
            let reserved_future_use = (data[3] >> 1) & 0b1111111;
            let NPT_time =
              ((data[3] & 0b1) << 32) |
              (data[4] << 24) |
              (data[5] << 16) |
              (data[6] << 8) |
              data[7];
            resObj.ActivationTime.reserved_future_use = reserved_future_use;
            resObj.ActivationTime.NPT_time = NPT_time;
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
            resObj.ActivationTime.reserved_future_use = reserved_future_use;
            resObj.ActivationTIme.eventRelativeTime = eventRelativeTime;
            break;

          default:
            break;
        }
        break;
      }

      case ModuleInfoDescriptor.CompressionType: {
        let compression_type = data[2];
        let original_size =
          (data[3] << 24) | (data[4] << 16) | (data[5] << 18) | data[6];
        resObj.CompressionType.compression_type = compression_type;
        resObj.CompressionType.original_size = original_size;
        break;
      }

      case ModuleInfoDescriptor.Control: {
        let control_data_byte = new Uint8Array(data, 2, descriptor_length);
        resObj.Control.control_data_byte = control_data_byte;
        break;
      }

      case ModuleInfoDescriptor.ProviderPrivate: {
        let private_scope_type = data[2];
        let scope_identifier =
          (data[3] << 24) | (data[4] << 16) | (data[5] << 18) | data[6];
        let n = descriptor_length - 5;

        switch (private_scope_type) {
          case 0x01: {
            let network_id = (data[7] << 8) | data[8];
            let padding = (data[9] << 8) | data[10];
            resObj.ProviderPrivate.network_id = network_id;
            break;
          }
          case 0x02: {
            let network_id = (data[7] << 8) | data[8];
            let service_id = (data[9] << 8) | data[10];
            resObj.ProviderPrivate.network_id = network_id;
            resObj.service_id = service_id;
            break;
          }
          case 0x03: {
            let network_id = (data[7] << 8) | data[8];
            let broadcaster_id = data[9];
            resObj.ProviderPrivate.network_id = network_id;
            resObj.ProviderPrivate.broadcaster_id = broadcaster_id;
            break;
          }
          case 0x04: {
            let bouquet_id = (data[7] << 8) | data[8];
            resObj.ProviderPrivate.bouquet_id = bouquet_id;
            break;
          }
          case 0x05: {
            let information_provider_id = (data[7] << 8) | data[8];
            resObj.ProviderPrivate.information_provider_id =
              information_provider_id;

            break;
          }
          case 0x06: {
            let CA_system_id = (data[7] << 8) | data[8];
            resObj.ProviderPrivate.CA_system_id = CA_system_id;
            break;
          }

          default:
            break;
        }

        break;
      }

      case ModuleInfoDescriptor.StoreRoot: {
        let update_type = data[2] & 0b1;
        let reserved = (data[2] >> 1) & 0b1111111;
        let store_root_path = new Uint8Array(data, 3, descriptor_length);
        resObj.StoreRoot.update_type = update_type;
        resObj.StoreRoot.store_root_path = new TextDecoder().decode(
          store_root_path
        );
        break;
      }

      case ModuleInfoDescriptor.SubDirectory: {
        let subdirectory_path = new Uint8Array(data, 3, descriptor_length);
        resObj.SubDirectory.subdirectory_path = new TextDecoder().decode(
          subdirectory_path
        );
        break;
      }

      case ModuleInfoDescriptor.Title: {
        let ISO_639_language_code =
          (data[2] << 24) | (data[3] << 16) | (data[4] << 8) | data[5];
        resObj.Title.ISO_639_language_code = ISO_639_language_code;
        let text_char = new Uint8Array(data, 6, descriptor_length - 1);
        resObj.Title.text = new TextDecoder().decode(text_char);
        break;
      }

      case ModuleInfoDescriptor.DataEncoding: {
        let data_component_id = (data[2] << 8) | data[3];
        let additional_data_encoding_info = new Uint8Array(
          data,
          4,
          descriptor_length
        );
        resObj.DataEncoding.data_compoent_id = data_component_id;
        resObj.DataEncoding.additional_data_encoding_info =
          additional_data_encoding_info;
        break;
      }

      case ModuleInfoDescriptor.RootCert: {
        let root_certificate_type = data[2] & 0b1;
        let reserved = (data[2] >> 1) & 0b1111111;
        resObj.RootCert.root_certificate_type = root_certificate_type;
        let certArray: Array<any> = [];
        let n = descriptor_length - 1;
        if (root_certificate_type == 0) {
          for (let i = 0; i < n; i++) {
            let certElement: any;
            let root_certificate_id =
              (data[3 + i] << 24) |
              (data[4 + i] << 16) |
              (data[5 + i] << 8) |
              data[6 + i];
            let root_certificate_version =
              (data[7 + i] << 24) |
              (data[8 + i] << 16) |
              (data[9 + i] << 8) |
              data[10 + i];
            certElement.root_certificate_id = root_certificate_id;
            certElement.root_certificate_version = root_certificate_version;
            certArray.push(certElement);
          }
          resObj.certArray = certArray;
        }
        break;
      }

      default:
        break;
    }
    return [offset, resObj];
  }

  ProcessDii(
    data: Uint8Array,


    pid: number
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
    let numberOfModules = (data[18 + descLen] << 8) | data[19 + descLen];
    let newBasePosition = 20 + descLen;
    let dlData = new DlData();
    dlData.ServiceId = this.serviceId;
    dlData.DownloadId = downloadId;
    dlData.BlockSize = blockSize;
    dlData.WindowSize = windowSize;
    dlData.AckPriod = ackPeriod;
    dlData.TcDownloadWindow = tCDownloadWindow;
    dlData.TcDownloadScenario = tCDownloadScenario;
    dlData.NumberOfModules = numberOfModules;
    dlData.ComponentTag = this.componentTag;
    for (let i = 0; i < numberOfModules; i++) {
      var moduleObj: any = {
        moduleId: (data[newBasePosition + 0] << 8) | data[newBasePosition + 1],
        moduleSize:
          (data[newBasePosition + 2] << 24) |
          (data[newBasePosition + 3] << 16) |
          (data[newBasePosition + 4] << 8) |
          data[newBasePosition + 5],
        moduleVersion: data[newBasePosition + 6],
        moduleInfoLength: data[newBasePosition + 7],
        status,
      };

      moduleObj.status.completeFlag = true;
      moduleObj.status.block = new Array<boolean>(1024);
      moduleObj.status.download = new Uint8Array();
      moduleObj.blockNumber = ((moduleObj.moduleSize - 1) / blockSize) + 1;

      var moduleInfoByte = new Uint8Array(moduleObj.moduleInfoLength);
      for (let j = 0; j < moduleObj.moduleInfoLength;) {
        // moduleInfoByte[j] = data[28 + j];
        let res = this.ProcessDescriptor(
          new Uint8Array(data, newBasePosition + 8 + j),
          moduleObj.moduleInfoLength
        );
        j += res[0];
        for (const key in res[1]) {
          moduleObj[key] = res[1][key];
        }
      }

      dlData.Module[i] = moduleObj;
      newBasePosition += moduleObj.moduleInfoLength + 8;

      // this.moduleMap.set(moduleObj.moduleId, moduleObj);
      // this.moduleByteMap.set(moduleObj.moduleId, moduleInfoByte);
    }

    let privateDataLength =
      (data[newBasePosition + 0] << 8) | data[newBasePosition + 1];
    let updatedFlag = false;
    let moduleUpdate = new Array(128);

    if (this.downloadDataMap.has(pid)) {
      let oldData = this.downloadDataMap.get(pid);
      for (let iNew = 0; iNew < dlData.NumberOfModules; iNew++) {
        moduleUpdate[iNew] = true;
      }

      for (let iOld = 0; iOld < oldData.NumberOfModules; iOld++) {
        let findFlag = false;
        let freeFlag = true;

        for (let iNew = 0; iNew < dlData.NumberOfModules && !findFlag; iNew++) {
          if (oldData.Module[iOld].id == dlData.Module[iNew].id) {
            if (oldData.Module[iOld].version != dlData.Module[iNew].version) {
              updatedFlag = true;
            } else {
              dlData.Module[iNew] = oldData.Module[iOld];
              moduleUpdate[iNew] = false;
              freeFlag = false;
            }
            findFlag = true;
          }
        }

        if (!findFlag) {
          //TODO:Complete delete module files
        }
      }
      this.downloadDataMap.set(pid, dlData);
    } else {
      this.downloadDataMap.set(pid, dlData);
      updatedFlag = true;
      for (let i = 0; i < dlData.NumberOfModules; i++) {
        moduleUpdate[i] = true;
      }
    }

    // let privateData = new Uint8Array(privateDataLength);
    //
    // for (let i = 0; i < privateDataLength; i++) {
    //     privateData[i] =
    //         (data[29 + numberOfModules + i] & 0b1111) |
    //         ((data[30 + numberOfModules + i] >> 4) & 0b1111);
    // }

    return 30 + numberOfModules + privateDataLength; // offset
  }

  ProcessDsmccDownloadDataHeader(data: Uint8Array): any {
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
    let offset = 12 + adaptationLength;
    return [offset, downloadId, adaptationLength, messageLength];
  }

  ProcessContent(serviceId: number, componentTag: number, moduleId: number, version: number, data: Uint8Array, contentType: string, len: number) {

    if (!contentType.includes("multipart/mixed")) {
      //It may be Single Part
      let resources = mimeParser(data);


    }
  }

  ProcessDDB(data: Uint8Array, pid: number): void {
    let newBasePosition = 0;
    let res = this.ProcessDsmccDownloadDataHeader(data);
    let offset: number = res[0];

    let downloadId: number = res[1];
    newBasePosition += offset;

    let moduleId = (data[newBasePosition + 0] << 8) | data[newBasePosition + 1];
    let moduleVersion = data[newBasePosition + 2];
    let reserved = data[newBasePosition + 3];
    let blockNumber = (data[newBasePosition + 4] << 8) | data[newBasePosition + 5];

    // ダウンロード情報が存在しない場合
    if (!this.downloadDataMap.has(pid)) {
      return;
    }

    //downloadIdが違う場合
    let dlData: DlData = this.downloadDataMap.get(pid);
    if (dlData.DownloadId != downloadId) {
      return;
    }

    let moduleIndex = -1;
    for (let i = 0; i < dlData.NumberOfModules; i++) {
      if (dlData.Module[i].moduleId == moduleId) {
        moduleIndex = i;
        break;
      }
    }
    //moduleIdに該当する情報が見つからない
    if (moduleIndex == -1) {
      return;
    }

    newBasePosition += 6;

    if (blockNumber >= 1023) {
      return;
    }

    let downloadData = new Uint8Array(data, newBasePosition)

    dlData.Module[moduleIndex].status.block[blockNumber] = true;
    let completeFlag = true;

    for (let i = 0; i < dlData.Module[moduleIndex].blockNumber; i++) {
      if (!dlData.Module[moduleIndex].status.block[i]) {
        completeFlag = false;
        break;
      }

    }

    if (completeFlag) {
      dlData.Module[moduleIndex].status.completeFlag = true;
      if ("CompressionType" in dlData.Module[moduleIndex]) {
        let compressedData = new RawInflate(downloadData);
        let decompressedData = compressedData.decompress();
        //TODO: Implement parse content 
      }
    }

  }

  ProcessDsmccSection(data: Uint8Array, pid: number): void {
    let table_id = data[0];
    let section_syntax_indicator = (data[1] >> 7) & 0b1;
    let private_indicator = (data[1] >> 6) & 0b1;
    let reserved1 = (data[1] >> 5) & 0b11;
    let dsmcc_section_length = ((data[1] & 0b1111) << 8) | data[2];
    let table_id_extension = (data[3] << 8) | data[4];
    let reserved2 = (data[5] >> 6) & 0b11;
    let version_number = (data[5] >> 3) & 0b11111;
    let current_next_indicator = data[5] & 0b1;
    let section_number = data[6];
    let last_section_number = data[7];

    switch (table_id) {
      case 0x3b:
        // this.ProcessDii(data.subarray(8));
        break;
      case 0x3c:
        this.ProcessDDB(new Uint8Array(data, 8, dsmcc_section_length - 9), pid);
        break;
      case 0x3e:
        break;
      default:
        break;
    }
  }
}
