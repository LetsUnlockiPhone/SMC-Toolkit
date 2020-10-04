import numpy as np
import os
import sys
from termcolor import cprint
import zlib


THIS_FOLDER = os.path.dirname(os.path.abspath(__file__))
smc_type = ''

def stringify_address(address):
	hexify = hex(address)
	stringify = str(hexify).replace('0x', '')
	prefix = '0'
	while len(stringify) < 8:
		stringify = prefix + stringify
	return stringify.upper()

def getfiles(path):
	absolute_path = os.path.join(THIS_FOLDER, path)
	file_list = sorted(os.listdir(absolute_path),  key=str.casefold)
	cleansed  = []
	for file in file_list:
		if file != '.DS_Store':
			cleansed.append(file)
	return cleansed

def chunk(path, file, name):
	global smc_type
	
	absolute_path = os.path.join(THIS_FOLDER, path)

	with open(absolute_path + '/' + file, 'r') as f:

		chunkArray = bytearray()
		count = 0
		block = ''
		filename = ''
		filename_count = 0

		for line in f:

			if line[:1] == 'S':
				
				if line[2:5] == '256':	
					smc_type = 'new'
				else:
					smc_type = 'old'
			
			if line[:1] == 'D' and count <= 30:
				
				block = line[2:10]
				print('chunking:', block, 'of', file)
				filename = block + '.bin'
				extract = line[14:142]
				line_bytes = bytes.fromhex(extract)
				chunkArray.extend(line_bytes)
				count += 1

			elif line[:1] == '+' and count <= 30:
				extract = line[14:142]
				line_bytes = bytes.fromhex(extract)
				chunkArray.extend(line_bytes)
				count += 1

			elif line[:1] == '+' and count == 31:
				extract = line[14:142]
				line_bytes = bytes.fromhex(extract)
				chunkArray.extend(line_bytes)
				count = 0

				save_path = os.path.join(THIS_FOLDER, 'extracted/' + name)
				path_exist = os.path.exists(save_path)
				
				if path_exist == True:
					if len(str(filename_count)) < 2:
						stringed_filename_count = '0' + str(filename_count)
					else:
						stringed_filename_count = str(filename_count)

					with open(save_path + '/' + stringed_filename_count + '_' + filename, 'wb') as w:
						w.write(chunkArray)
						w.close()
				
				else:
					
					if len(str(filename_count)) < 2:
						stringed_filename_count = '0' + str(filename_count)
					else:
						stringed_filename_count = str(filename_count)

					os.makedirs(save_path)
					
					with open(save_path + '/' + stringed_filename_count + '_' + filename, 'wb') as w:
						w.write(chunkArray)
						w.close()

				filename_count += 1
				chunkArray = bytearray() # reinitailize / clear bytearray
			
		f.close()

def reconstruct():

	ranges = {'ranges':[]}
	start = 0
	chunk = 2048
	total = 262144
	final = bytearray()

	# create address ranges and store in dictionary array
	while start < total:
		block = {stringify_address(start): b''}
		ranges['ranges'].append(block)
		start += chunk

	absolute_path = os.path.join(THIS_FOLDER, 'extracted')
	for directory in sorted(os.listdir(absolute_path), key=str.casefold):

		if directory != '.DS_Store' and directory != 'firmware': #.DS_Store =  Mac problem only	
			for filename in sorted(os.listdir(absolute_path + '/' + directory)):
				for item in ranges['ranges']:
					for key, value in item.items():
						if key == filename[3:11]:
							with open(absolute_path + '/' + directory + '/' + filename, 'rb') as f:
								data = f.read()
								item[key] = data

	for item in ranges['ranges']:
		for key, value in item.items():
			if value == b'':
				item[key] = generate_fill()

	for item in ranges['ranges']:
		for key, value in item.items():
			final.extend(value)

	path = absolute_path + '/firmware'
	path_exist = os.path.exists(path)
	if path_exist == True:
		with open(path + '/firmware.bin', 'wb') as w:
			w.write(final)
			w.close()	
	else:
		os.makedirs(path)		
		with open(path + '/firmware.bin', 'wb') as w:
			w.write(final)
			w.close()


def generate_fill():
	fill_byte = b'\xFF'
	fill = bytearray()
	count = 2048

	while count > 0:
		fill.extend(fill_byte)
		count -= 1

	return fill

def verify_adler32():
	firmware = os.path.join(THIS_FOLDER, 'extracted/firmware/firmware.bin')
	with open(firmware, 'rb') as f:

		# offsets in decimal
		vectors_table_start = 0 
		vectors_table_size = 2044
		vectors_table_adler = 2044
		flasher_base_start = 2048
		flasher_base_size = 20472
		flasher_base_adler = 22520
		flasher_update_start = 22528
		flasher_update_size = 20472
		flasher_update_adler = 43000
		epm_part1_start = 43008
		epm_part1_size = 2040
		epm_part1_adler = 45048
		epm_part2_start = 45056
		epm_part2_size = 2040
		epm_part2_adler = 47096
		user = 0
		user_size = 0 
		user_adler = 0

		if smc_type == 'new':
			user_part1_start = 47104
			user_part1_size = 12284
			user_part1_adler = 59388

			user_part2_start = 59392
			user_part2_size = 202744
			user_part2_adler = 262136

		if smc_type == 'old':
			user_start = 47104
			user_size = 215032
			user_adler = 262136


		f.seek(vectors_table_start)
		vectors_table = f.read(vectors_table_size)
		f.seek(vectors_table_adler)
		vectors_table_adler_data = f.read(4)
		reversed_vectors_table_adler = np.flip(np.frombuffer(bytearray(vectors_table_adler_data), dtype=np.uint8, count=-1, offset=0),0).tobytes()
			
		f.seek(flasher_base_start)
		flasher_base = f.read(flasher_base_size)
		f.seek(flasher_base_adler)
		flasher_base_adler_data = f.read(4)
		reversed_flasher_base_adler = np.flip(np.frombuffer(bytearray(flasher_base_adler_data), dtype=np.uint8, count=-1, offset=0),0).tobytes()

		f.seek(flasher_update_start)
		flasher_update = f.read(flasher_update_size)
		f.seek(flasher_update_adler)
		flasher_update_adler_data = f.read(4)
		reversed_flasher_update_adler = np.flip(np.frombuffer(bytearray(flasher_update_adler_data), dtype=np.uint8, count=-1, offset=0),0).tobytes()

		f.seek(epm_part1_start)
		epm_part1 = f.read(epm_part1_size)
		f.seek(epm_part1_adler)
		epm_part1_adler_data = f.read(4)
		reversed_epm_part1_adler = np.flip(np.frombuffer(bytearray(epm_part1_adler_data), dtype=np.uint8, count=-1, offset=0),0).tobytes()

		f.seek(epm_part2_start)
		epm_part2 = f.read(epm_part2_size)
		f.seek(epm_part2_adler)
		epm_part2_adler_data = f.read(4)
		reversed_epm_part2_adler = np.flip(np.frombuffer(bytearray(epm_part2_adler_data), dtype=np.uint8, count=-1, offset=0),0).tobytes()

		if smc_type == 'new':
			f.seek(user_part1_start)
			user_part1 = f.read(user_part1_size)
			f.seek(user_part1_adler)
			user_part1_adler_data = f.read(4)
			reversed_user_part1_adler = np.flip(np.frombuffer(bytearray(user_part1_adler_data), dtype=np.uint8, count=-1, offset=0),0).tobytes()

			f.seek(user_part2_start)
			user_part2 = f.read(user_part2_size)
			f.seek(user_part2_adler)
			user_part2_adler_data = f.read(4)
			reversed_user_part2_adler = np.flip(np.frombuffer(bytearray(user_part2_adler_data), dtype=np.uint8, count=-1, offset=0),0).tobytes()
		
		if smc_type == 'old':
			f.seek(user_start)
			user = f.read(user_size)
			f.seek(user_adler)
			user_adler_data = f.read(4)
			reversed_user_adler = np.flip(np.frombuffer(bytearray(user_adler_data), dtype=np.uint8, count=-1, offset=0),0).tobytes()

		print('SMC Type Detected:', smc_type.upper())
		print('Vectors Table adler32 Calculation: ', hex(zlib.adler32(vectors_table) & 0xffffffff))
		print('Vectors Table adler32 in file:', '0x' + str(reversed_vectors_table_adler.hex()))
		if zlib.adler32(vectors_table) == int.from_bytes(vectors_table_adler_data, 'little'):
			cprint('Vectors Table CRC Verified', 'green')
		else:
			cprint('Vectors Table CRC Error', 'red')
			

		print('Flasher Base adler32 Calculation: ', hex(zlib.adler32(flasher_base) & 0xffffffff))
		print('Flasher Base adler32 in file:', '0x' + reversed_flasher_base_adler.hex())
		if zlib.adler32(flasher_base) == int.from_bytes(flasher_base_adler_data, 'little'):
			cprint('Flasher Base CRC Verified', 'green')
		else:
			cprint('Flasher Base CRC Error', 'red')

		print('Flasher Update adler32 Calculation: ', hex(zlib.adler32(flasher_update) & 0xffffffff))
		print('Flasher Update adler32 in file:', '0x' + reversed_flasher_update_adler.hex())
		if zlib.adler32(flasher_update) == int.from_bytes(flasher_update_adler_data, 'little'):
			cprint('Flasher Update CRC Verified', 'green')
		else:
			cprint('Flasher Update CRC Error', 'red')

		print('EPM Part 1 adler32 Calculation: ', hex(zlib.adler32(epm_part1) & 0xffffffff))
		print('EPM Part 1 adler32 in file:', '0x' + reversed_epm_part1_adler.hex())
		if zlib.adler32(epm_part1) == int.from_bytes(epm_part1_adler_data, 'little'):
			cprint('EPM Part 1 CRC Verified', 'green')
		else:
			cprint('EPM Part 1 CRC Error', 'red')

		print('EPM Part 2 adler32 Calculation: ', hex(zlib.adler32(epm_part2) & 0xffffffff))
		print('EPM Part 2 adler32 in file:', '0x' + reversed_epm_part2_adler.hex())
		if zlib.adler32(epm_part2) == int.from_bytes(epm_part2_adler_data, 'little'):
			cprint('EPM Part 2 CRC Verified', 'green')
		else:
			cprint('EPM Part 2 CRC Error', 'red')

		if smc_type == 'new':
			print('User Application Part 1 adler32 Calculation: ', hex(zlib.adler32(user_part1) & 0xffffffff))
			print('User Application Part 1 adler32 in file:', '0x' + reversed_user_part1_adler.hex())
			if zlib.adler32(user_part1) == int.from_bytes(user_part1_adler_data, 'little'):
				cprint('User Application Part 1 CRC Verified', 'green')
			else:
				cprint('User Application Part 1 CRC Error', 'red')

			print('User Application Part 2 adler32 Calculation: ', hex(zlib.adler32(user_part2) & 0xffffffff))
			print('User Application Part 2 adler32 in file:', '0x' + reversed_user_part2_adler.hex())
			if zlib.adler32(user_part2) == int.from_bytes(user_part2_adler_data, 'little'):
				cprint('User Application Part 2 CRC Verified', 'green')
			else:
				cprint('User Application Part 2 CRC Error', 'red')

		if smc_type == 'old':
			print('User Application adler32 Calculation: ', hex(zlib.adler32(user) & 0xffffffff))
			print('User Application adler32 in file:', '0x' + reversed_user_adler.hex())
			if zlib.adler32(user) == int.from_bytes(user_adler_data, 'little'):
				cprint('User Application CRC Verified', 'green')
			else:
				cprint('User Application CRC Error', 'red')


def main(path):

	absolute_path = os.path.join(THIS_FOLDER, path)
	files = getfiles(absolute_path)

	for file in files:
		name = file.replace('.', '_')
		chunk(absolute_path, file, name)

	reconstruct()

	verify_adler32()

path = sys.argv[1]
main(path)
print('finished')

# Notes:
# line length of 64 byte check / counter
# section count / check of 2048 bytes / 2kbs
# 262144 bytes = 256kb
