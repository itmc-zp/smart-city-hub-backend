import * as path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export const CAS = path.resolve(__dirname, 'CAs.Test.json');

export const CA_CERTIFICATES = [
  path.resolve(__dirname, 'CACertificates.Test.All.p7b'),
];

export const PKEY_PARAMETERS = {
  filePath: path.resolve(__dirname, 'Key-6.dat'),
  password: '12345',
  certificates: [path.resolve(__dirname, 'test-2108.cer')],
  CACommonName: 'Тестовий надавач електронних довірчих послуг',
};

