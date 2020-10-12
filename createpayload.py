import os
import sys
from itertools import islice

THIS_FOLDER = os.path.dirname(os.path.abspath(__file__))

def rs232_checksum(the_bytes):
	return b'%02X' % (sum(the_bytes) & 0xFF)
	
def stringify_address(address):
	hexify = hex(address)
	stringify = str(hexify).replace('0x', '')
	prefix = '0'
	while len(stringify) < 8:
		stringify = prefix + stringify
	return stringify.upper()

def generate_fill():
	fill_byte = b'\xFF'
	fill = bytearray()
	count = 2048

	while count > 0:
		fill.extend(fill_byte)
		count -= 1

	return fill

def generate_area(ranges, start, end):
	area = bytearray()
	location = start
	chunk = 2048
	while location >= start and location < end:
		for item in ranges['ranges']:
			for key, value in item.items():
				if key == stringify_address(location):
					area.extend(item[key])
		location += chunk
	return area

def chunked(iterable, n):
	it = iter(iterable)
	values = bytes(islice(it, n))
	while values:
		yield values
		values = bytes(islice(it, n))

def convert_to_bytes(byte_array, size):
	final_header_array = []
	sub_array = bytearray()

	for array in byte_array:
		for item in array:
			new_item = int(item, 16)
			converted = new_item.to_bytes(size, 'little')
			sub_array.extend(converted)
		final_header_array.append(sub_array)
		sub_array = bytearray()

	return final_header_array

def bytes_to_checksum(bytes_array):
	header = header_payload(rs232_checksum(bytes_array))
	return header

def sort_bytearray(bytes_array):
	completed = []
	for array in bytes_array:
		completed.append(bytes_to_checksum(array))
	return completed

def header_payload(checksum):
	final_header_array = []
	sig_array = []
	
	# calculate header padding size
	difference = 20 - int(len(checksum)/2) - 1 #need to subtract extra because byte is 2 characters
	header_padding_array = []
	while difference >= 0:
		header_padding_array.append('00')
		difference -= 1

	final_padding = ''.join(header_padding_array)
	final_header_hash = str(checksum).replace("b'","").replace("'","") + final_padding
	final_header_array.append('H:' + str(int(len(final_header_hash)/2)) + ':' + final_header_hash + ':' + str(checksum).replace("b'","").replace("'",""))
	return final_header_array

def security_payload(checksum):
	final_header_array = []
	sig_array = []
	
	# calculate header padding size
	difference = 20 - int(len(checksum)/2) - 1 #need to subtract extra because byte is 2 characters
	header_padding_array = []
	while difference >= 0:
		header_padding_array.append('00')
		difference -= 1

	final_padding = ''.join(header_padding_array)
	final_header_hash = str(checksum).replace("b'","").replace("'","") + final_padding
	final_header_array.append('S:' + str(int(len(final_header_hash)/2)) + ':' + final_header_hash + ':' + str(checksum).replace("b'","").replace("'",""))
	return final_header_array

def generate_security_header(vectors_header, additional_header):
	header = sort_bytearray(convert_to_bytes(vectors_header + additional_header, 1))
	security = convert_to_bytes(vectors_header + additional_header, 1)
	array = []
	for item in security:
		x = str(rs232_checksum(item)).replace("b'","").replace("'","")
		x_int = int(x, 16)
		array.append(x_int)
	security_checksum = security_payload(rs232_checksum(array))
	return security_checksum

def create_final_payload(header, vectors, payload):
	header_array = []
	for array in header:
		for item in array:
			header_array.append(item)

	final_header = '\n'.join(header_array)
	final_vectors = '\n'.join(vectors)
	final_payload = '\n'.join(payload)

	final = final_header + '\n' + final_vectors + '\n' + final_payload + '\n'
	return final

def write_payload(version, payload, filename):
	path = os.path.join(THIS_FOLDER, 'payload')
	path_exist = os.path.exists(path)

	if path_exist == True:
		with open(path + '/' + filename, 'w') as writefile:
			writefile.write('# Version: ' + version + '\n' )
			writefile.write(payload)
			writefile.close()	
	else:
		os.makedirs(path)		
		with open(path + '/' + filename, 'w') as writefile:
			writefile.write('# Version: ' + version + '\n' )
			writefile.write(payload)
			writefile.close()

def create_payload(chunk, start):
	# Initialize Variables
	header_array = []
	hex_counter = start
	line_counter = 0
	omit_counter = 0
	omit_bytes = b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'
	header_payload_array = []	
	payload_array = []
	chunk_array = []
	final_header_array = []

	for block_bytes in chunked(chunk, n=64):

		if line_counter == 0:
			length = len(hex(hex_counter).replace('0x',''))
			total = 8 - length
			prefix = ['D:']
				
			while total > 0:
				prefix.append('0')
				total -= 1

			final_prefix = ''.join(prefix)
			chunk_array.append(final_prefix + hex(hex_counter).replace('0x','').upper() + ':' + str(len(block_bytes)) + ':' + block_bytes.hex().upper() + ':' + str(rs232_checksum(block_bytes)).replace("b'","").replace("'",""))
			header_array.append(str(rs232_checksum(block_bytes)).replace("b'","").replace("'",""))
			hex_counter += 64
			if block_bytes == omit_bytes:
				omit_counter += 1

		if line_counter != 0:
			chunk_array.append('+         :' + str(len(block_bytes)) + ':' + block_bytes.hex().upper() + ':' + str(rs232_checksum(block_bytes)).replace("b'","").replace("'",""))
			header_array.append(str(rs232_checksum(block_bytes)).replace("b'","").replace("'",""))
			hex_counter += 64
			if block_bytes == omit_bytes:
				omit_counter += 1

		line_counter += 64

		if line_counter == 2048:
			line_counter = 0
			if omit_counter < 32:
				final_header_array.append(header_array)
				payload_array.extend(chunk_array)
				chunk_array = []
				omit_counter = 0
				header_array = []
			else:
				chunk_array = []
				omit_counter = 0
				header_array = []
	
	return final_header_array, payload_array


def main(file, version):
	smc_type = 'OLD'
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

	start = 0 # reinitialize start
	with open(file, 'rb') as f:
		
		while start < total:
			f.seek(start)
			data = f.read(chunk)
			for item in ranges['ranges']:
				for key, value in item.items():
					if key == stringify_address(start):
						item[key] = data
			start += chunk

	vectors_table_start = 0
	flasher_base_start = 2048
	flasher_update_start = 22528
	epm1_start = 43008
	epm2_start = 45056
	user1_start = 47104
	user2_start = 59392
	end = 262144

	
	vectors_table_area = generate_area(ranges, vectors_table_start, flasher_base_start)
	
	flasher_base_area = generate_area(ranges, flasher_base_start, flasher_update_start)
	flasher_update_area = generate_area(ranges,flasher_update_start, epm1_start)
	epm1_area = generate_area(ranges, epm1_start, epm2_start)
	epm2_area = generate_area(ranges, epm2_start, user1_start)
	epm_area = epm2_area + epm1_area

	if smc_type == 'OLD':
		user_area = generate_area(ranges, user1_start, end)
	if smc_type == 'NEW':
		user1_area = generate_area(ranges, user1_start, user2_start)
		user2_area = generate_area(ranges, user2_start, end)
		user_area = user1_area + user2_area

	print('creating payloads...')
	vectors_header, vectors_table_payload = create_payload(vectors_table_area, vectors_table_start)
	
	flasher_base_header, flasher_base_payload = create_payload(flasher_base_area, flasher_base_start)
	fb_header = sort_bytearray(convert_to_bytes(vectors_header + flasher_base_header, 1))
	fb_security = generate_security_header(vectors_header, flasher_base_header)
	fb_header.append(fb_security)
	fb_final = create_final_payload(fb_header, vectors_table_payload, flasher_base_payload)
	
	
	flasher_update_header, flasher_update_payload = create_payload(flasher_update_area, flasher_update_start)
	fu_header = sort_bytearray(convert_to_bytes(vectors_header + flasher_update_header, 1))
	fu_security = generate_security_header(vectors_header, flasher_update_header)
	fu_header.append(fu_security)
	fu_final = create_final_payload(fu_header, vectors_table_payload, flasher_update_payload)

	# To Do: decipher epm
	#epm_payload = create_payload(epm_area, start_address?)

	user_header, user_payload = create_payload(user_area, user1_start)
	u_header = sort_bytearray(convert_to_bytes(vectors_header + user_header, 1))
	u_security = generate_security_header(vectors_header, user_header)
	u_header.append(u_security)
	u_final = create_final_payload(u_header, vectors_table_payload, user_payload)

	# Write Files:
	write_payload(version, fb_final, 'flasher_base.smc')
	write_payload(version, fu_final, 'flasher_update.smc')
	# To Do: decipher epm
	#write_payload(version, header, payload, 'firmware.epm')
	write_payload(version, u_final, 'Mac-BoardID.smc')
	


file = sys.argv[1]
version = sys.argv[2]
main(file, version)
print('finished')
