/**
 * cgltf - a glTF 2.0 library written in C99.
 *
 * Version: 1.11
 *
 * Website: https://github.com/gilmorem560/cgltf
 *
 * Distributed under the MIT License, see notice at the end of this file.
 */
#include <float.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <jsmn.h>

#include "cgltf.h"

const cgltf_size GlbHeaderSize = 12;
const cgltf_size GlbChunkHeaderSize = 8;
const uint32_t GlbVersion = 2;
const uint32_t GlbMagic = 0x46546C67;
const uint32_t GlbMagicJsonChunk = 0x4E4F534A;
const uint32_t GlbMagicBinChunk = 0x004E4942;

void* cgltf_default_alloc(void* user, cgltf_size size)
{
	(void)user;
	return CGLTF_MALLOC(size);
}

void cgltf_default_free(void* user, void* ptr)
{
	(void)user;
	CGLTF_FREE(ptr);
}

void* cgltf_calloc(cgltf_options* options, size_t element_size, cgltf_size count)
{
	if (SIZE_MAX / element_size < count)
	{
		return NULL;
	}
	void* result = options->memory.alloc(options->memory.user_data, element_size * count);
	if (!result)
	{
		return NULL;
	}
	memset(result, 0, element_size * count);
	return result;
}

cgltf_result cgltf_default_file_read(const struct cgltf_memory_options* memory_options, const struct cgltf_file_options* file_options, const char* path, cgltf_size* size, void** data)
{
	(void)file_options;
	void* (*memory_alloc)(void*, cgltf_size) = memory_options->alloc ? memory_options->alloc : &cgltf_default_alloc;
	void (*memory_free)(void*, void*) = memory_options->free ? memory_options->free : &cgltf_default_free;

	FILE* file = fopen(path, "rb");
	if (!file)
	{
		return cgltf_result_file_not_found;
	}

	cgltf_size file_size = size ? *size : 0;

	if (file_size == 0)
	{
		fseek(file, 0, SEEK_END);

		long length = ftell(file);
		if (length < 0)
		{
			fclose(file);
			return cgltf_result_io_error;
		}

		fseek(file, 0, SEEK_SET);
		file_size = (cgltf_size)length;
	}

	char* file_data = (char*)memory_alloc(memory_options->user_data, file_size);
	if (!file_data)
	{
		fclose(file);
		return cgltf_result_out_of_memory;
	}
	
	cgltf_size read_size = fread(file_data, 1, file_size, file);

	fclose(file);

	if (read_size != file_size)
	{
		memory_free(memory_options->user_data, file_data);
		return cgltf_result_io_error;
	}

	if (size)
	{
		*size = file_size;
	}
	if (data)
	{
		*data = file_data;
	}

	return cgltf_result_success;
}

void cgltf_default_file_release(const struct cgltf_memory_options* memory_options, const struct cgltf_file_options* file_options, void* data)
{
	(void)file_options;
	void (*memfree)(void*, void*) = memory_options->free ? memory_options->free : &cgltf_default_free;
	memfree(memory_options->user_data, data);
}

cgltf_result cgltf_parse(const cgltf_options* options, const void* data, cgltf_size size, cgltf_data** out_data)
{
	if (size < GlbHeaderSize)
	{
		return cgltf_result_data_too_short;
	}

	if (options == NULL)
	{
		return cgltf_result_invalid_options;
	}

	cgltf_options fixed_options = *options;
	if (fixed_options.memory.alloc == NULL)
	{
		fixed_options.memory.alloc = &cgltf_default_alloc;
	}
	if (fixed_options.memory.free == NULL)
	{
		fixed_options.memory.free = &cgltf_default_free;
	}

	uint32_t tmp;
	// Magic
	memcpy(&tmp, data, 4);
	if (tmp != GlbMagic)
	{
		if (fixed_options.type == cgltf_file_type_invalid)
		{
			fixed_options.type = cgltf_file_type_gltf;
		}
		else if (fixed_options.type == cgltf_file_type_glb)
		{
			return cgltf_result_unknown_format;
		}
	}

	if (fixed_options.type == cgltf_file_type_gltf)
	{
		cgltf_result json_result = cgltf_parse_json(&fixed_options, (const uint8_t*)data, size, out_data);
		if (json_result != cgltf_result_success)
		{
			return json_result;
		}

		(*out_data)->file_type = cgltf_file_type_gltf;

		return cgltf_result_success;
	}

	const uint8_t* ptr = (const uint8_t*)data;
	// Version
	memcpy(&tmp, ptr + 4, 4);
	uint32_t version = tmp;
	if (version != GlbVersion)
	{
		return version < GlbVersion ? cgltf_result_legacy_gltf : cgltf_result_unknown_format;
	}

	// Total length
	memcpy(&tmp, ptr + 8, 4);
	if (tmp > size)
	{
		return cgltf_result_data_too_short;
	}

	const uint8_t* json_chunk = ptr + GlbHeaderSize;

	if (GlbHeaderSize + GlbChunkHeaderSize > size)
	{
		return cgltf_result_data_too_short;
	}

	// JSON chunk: length
	uint32_t json_length;
	memcpy(&json_length, json_chunk, 4);
	if (GlbHeaderSize + GlbChunkHeaderSize + json_length > size)
	{
		return cgltf_result_data_too_short;
	}

	// JSON chunk: magic
	memcpy(&tmp, json_chunk + 4, 4);
	if (tmp != GlbMagicJsonChunk)
	{
		return cgltf_result_unknown_format;
	}

	json_chunk += GlbChunkHeaderSize;

	const void* bin = 0;
	cgltf_size bin_size = 0;

	if (GlbHeaderSize + GlbChunkHeaderSize + json_length + GlbChunkHeaderSize <= size)
	{
		// We can read another chunk
		const uint8_t* bin_chunk = json_chunk + json_length;

		// Bin chunk: length
		uint32_t bin_length;
		memcpy(&bin_length, bin_chunk, 4);
		if (GlbHeaderSize + GlbChunkHeaderSize + json_length + GlbChunkHeaderSize + bin_length > size)
		{
			return cgltf_result_data_too_short;
		}

		// Bin chunk: magic
		memcpy(&tmp, bin_chunk + 4, 4);
		if (tmp != GlbMagicBinChunk)
		{
			return cgltf_result_unknown_format;
		}

		bin_chunk += GlbChunkHeaderSize;

		bin = bin_chunk;
		bin_size = bin_length;
	}

	cgltf_result json_result = cgltf_parse_json(&fixed_options, json_chunk, json_length, out_data);
	if (json_result != cgltf_result_success)
	{
		return json_result;
	}

	(*out_data)->file_type = cgltf_file_type_glb;
	(*out_data)->bin = bin;
	(*out_data)->bin_size = bin_size;

	return cgltf_result_success;
}

cgltf_result cgltf_parse_file(const cgltf_options* options, const char* path, cgltf_data** out_data)
{
	if (options == NULL)
	{
		return cgltf_result_invalid_options;
	}

	void (*memory_free)(void*, void*) = options->memory.free ? options->memory.free : &cgltf_default_free;
	cgltf_result (*file_read)(const struct cgltf_memory_options*, const struct cgltf_file_options*, const char*, cgltf_size*, void**) = options->file.read ? options->file.read : &cgltf_default_file_read;

	void* file_data = NULL;
	cgltf_size file_size = 0;
	cgltf_result result = file_read(&options->memory, &options->file, path, &file_size, &file_data);
	if (result != cgltf_result_success)
	{
		return result;
	}

	result = cgltf_parse(options, file_data, file_size, out_data);

	if (result != cgltf_result_success)
	{
		memory_free(options->memory.user_data, file_data);
		return result;
	}

	(*out_data)->file_data = file_data;

	return cgltf_result_success;
}

void cgltf_combine_paths(char* path, const char* base, const char* uri)
{
	const char* s0 = strrchr(base, '/');
	const char* s1 = strrchr(base, '\\');
	const char* slash = s0 ? (s1 && s1 > s0 ? s1 : s0) : s1;

	if (slash)
	{
		size_t prefix = slash - base + 1;

		strncpy(path, base, prefix);
		strcpy(path + prefix, uri);
	}
	else
	{
		strcpy(path, uri);
	}
}

cgltf_result cgltf_load_buffer_file(const cgltf_options* options, cgltf_size size, const char* uri, const char* gltf_path, void** out_data)
{
	void* (*memory_alloc)(void*, cgltf_size) = options->memory.alloc ? options->memory.alloc : &cgltf_default_alloc;
	void (*memory_free)(void*, void*) = options->memory.free ? options->memory.free : &cgltf_default_free;
	cgltf_result (*file_read)(const struct cgltf_memory_options*, const struct cgltf_file_options*, const char*, cgltf_size*, void**) = options->file.read ? options->file.read : &cgltf_default_file_read;

	char* path = (char*)memory_alloc(options->memory.user_data, strlen(uri) + strlen(gltf_path) + 1);
	if (!path)
	{
		return cgltf_result_out_of_memory;
	}

	cgltf_combine_paths(path, gltf_path, uri);

	// after combining, the tail of the resulting path is a uri; decode_uri converts it into path
	cgltf_decode_uri(path + strlen(path) - strlen(uri));

	void* file_data = NULL;
	cgltf_result result = file_read(&options->memory, &options->file, path, &size, &file_data);

	memory_free(options->memory.user_data, path);

	*out_data = (result == cgltf_result_success) ? file_data : NULL;

	return result;
}

cgltf_result cgltf_load_buffer_base64(const cgltf_options* options, cgltf_size size, const char* base64, void** out_data)
{
	void* (*memory_alloc)(void*, cgltf_size) = options->memory.alloc ? options->memory.alloc : &cgltf_default_alloc;
	void (*memory_free)(void*, void*) = options->memory.free ? options->memory.free : &cgltf_default_free;

	unsigned char* data = (unsigned char*)memory_alloc(options->memory.user_data, size);
	if (!data)
	{
		return cgltf_result_out_of_memory;
	}

	unsigned int buffer = 0;
	unsigned int buffer_bits = 0;

	for (cgltf_size i = 0; i < size; ++i)
	{
		while (buffer_bits < 8)
		{
			char ch = *base64++;

			int index =
				(unsigned)(ch - 'A') < 26 ? (ch - 'A') :
				(unsigned)(ch - 'a') < 26 ? (ch - 'a') + 26 :
				(unsigned)(ch - '0') < 10 ? (ch - '0') + 52 :
				ch == '+' ? 62 :
				ch == '/' ? 63 :
				-1;

			if (index < 0)
			{
				memory_free(options->memory.user_data, data);
				return cgltf_result_io_error;
			}

			buffer = (buffer << 6) | index;
			buffer_bits += 6;
		}

		data[i] = (unsigned char)(buffer >> (buffer_bits - 8));
		buffer_bits -= 8;
	}

	*out_data = data;

	return cgltf_result_success;
}

int cgltf_unhex(char ch)
{
	return
		(unsigned)(ch - '0') < 10 ? (ch - '0') :
		(unsigned)(ch - 'A') < 6 ? (ch - 'A') + 10 :
		(unsigned)(ch - 'a') < 6 ? (ch - 'a') + 10 :
		-1;
}

void cgltf_decode_uri(char* uri)
{
	char* write = uri;
	char* i = uri;

	while (*i)
	{
		if (*i == '%')
		{
			int ch1 = cgltf_unhex(i[1]);

			if (ch1 >= 0)
			{
				int ch2 = cgltf_unhex(i[2]);

				if (ch2 >= 0)
				{
					*write++ = (char)(ch1 * 16 + ch2);
					i += 3;
					continue;
				}
			}
		}

		*write++ = *i++;
	}

	*write = 0;
}

cgltf_result cgltf_load_buffers(const cgltf_options* options, cgltf_data* data, const char* gltf_path)
{
	if (options == NULL)
	{
		return cgltf_result_invalid_options;
	}

	if (data->buffers_count && data->buffers[0].data == NULL && data->buffers[0].uri == NULL && data->bin)
	{
		if (data->bin_size < data->buffers[0].size)
		{
			return cgltf_result_data_too_short;
		}

		data->buffers[0].data = (void*)data->bin;
	}

	for (cgltf_size i = 0; i < data->buffers_count; ++i)
	{
		if (data->buffers[i].data)
		{
			continue;
		}

		const char* uri = data->buffers[i].uri;

		if (uri == NULL)
		{
			continue;
		}

		if (strncmp(uri, "data:", 5) == 0)
		{
			const char* comma = strchr(uri, ',');

			if (comma && comma - uri >= 7 && strncmp(comma - 7, ";base64", 7) == 0)
			{
				cgltf_result res = cgltf_load_buffer_base64(options, data->buffers[i].size, comma + 1, &data->buffers[i].data);

				if (res != cgltf_result_success)
				{
					return res;
				}
			}
			else
			{
				return cgltf_result_unknown_format;
			}
		}
		else if (strstr(uri, "://") == NULL && gltf_path)
		{
			cgltf_result res = cgltf_load_buffer_file(options, data->buffers[i].size, uri, gltf_path, &data->buffers[i].data);

			if (res != cgltf_result_success)
			{
				return res;
			}
		}
		else
		{
			return cgltf_result_unknown_format;
		}
	}

	return cgltf_result_success;
}

cgltf_size cgltf_calc_index_bound(cgltf_buffer_view* buffer_view, cgltf_size offset, cgltf_component_type component_type, cgltf_size count)
{
	char* data = (char*)buffer_view->buffer->data + offset + buffer_view->offset;
	cgltf_size bound = 0;

	switch (component_type)
	{
	case cgltf_component_type_r_8u:
		for (size_t i = 0; i < count; ++i)
		{
			cgltf_size v = ((unsigned char*)data)[i];
			bound = bound > v ? bound : v;
		}
		break;

	case cgltf_component_type_r_16u:
		for (size_t i = 0; i < count; ++i)
		{
			cgltf_size v = ((unsigned short*)data)[i];
			bound = bound > v ? bound : v;
		}
		break;

	case cgltf_component_type_r_32u:
		for (size_t i = 0; i < count; ++i)
		{
			cgltf_size v = ((unsigned int*)data)[i];
			bound = bound > v ? bound : v;
		}
		break;

	default:
		;
	}

	return bound;
}

cgltf_result cgltf_validate(cgltf_data* data)
{
	for (cgltf_size i = 0; i < data->accessors_count; ++i)
	{
		cgltf_accessor* accessor = &data->accessors[i];

		cgltf_size element_size = cgltf_calc_size(accessor->type, accessor->component_type);

		if (accessor->buffer_view)
		{
			cgltf_size req_size = accessor->offset + accessor->stride * (accessor->count - 1) + element_size;

			CGLTF_ASSERT_IF(accessor->buffer_view->size < req_size, cgltf_result_data_too_short);
		}

		if (accessor->is_sparse)
		{
			cgltf_accessor_sparse* sparse = &accessor->sparse;

			cgltf_size indices_component_size = cgltf_calc_size(cgltf_type_scalar, sparse->indices_component_type);
			cgltf_size indices_req_size = sparse->indices_byte_offset + indices_component_size * sparse->count;
			cgltf_size values_req_size = sparse->values_byte_offset + element_size * sparse->count;

			CGLTF_ASSERT_IF(sparse->indices_buffer_view->size < indices_req_size ||
							sparse->values_buffer_view->size < values_req_size, cgltf_result_data_too_short);

			CGLTF_ASSERT_IF(sparse->indices_component_type != cgltf_component_type_r_8u &&
							sparse->indices_component_type != cgltf_component_type_r_16u &&
							sparse->indices_component_type != cgltf_component_type_r_32u, cgltf_result_invalid_gltf);

			if (sparse->indices_buffer_view->buffer->data)
			{
				cgltf_size index_bound = cgltf_calc_index_bound(sparse->indices_buffer_view, sparse->indices_byte_offset, sparse->indices_component_type, sparse->count);

				CGLTF_ASSERT_IF(index_bound >= accessor->count, cgltf_result_data_too_short);
			}
		}
	}

	for (cgltf_size i = 0; i < data->buffer_views_count; ++i)
	{
		cgltf_size req_size = data->buffer_views[i].offset + data->buffer_views[i].size;

		CGLTF_ASSERT_IF(data->buffer_views[i].buffer && data->buffer_views[i].buffer->size < req_size, cgltf_result_data_too_short);

		if (data->buffer_views[i].has_meshopt_compression)
		{
			cgltf_meshopt_compression* mc = &data->buffer_views[i].meshopt_compression;

			CGLTF_ASSERT_IF(mc->buffer == NULL || mc->buffer->size < mc->offset + mc->size, cgltf_result_data_too_short);

			CGLTF_ASSERT_IF(data->buffer_views[i].stride && mc->stride != data->buffer_views[i].stride, cgltf_result_invalid_gltf);

			CGLTF_ASSERT_IF(data->buffer_views[i].size != mc->stride * mc->count, cgltf_result_invalid_gltf);

			CGLTF_ASSERT_IF(mc->mode == cgltf_meshopt_compression_mode_invalid, cgltf_result_invalid_gltf);

			CGLTF_ASSERT_IF(mc->mode == cgltf_meshopt_compression_mode_attributes && !(mc->stride % 4 == 0 && mc->stride <= 256), cgltf_result_invalid_gltf);

			CGLTF_ASSERT_IF(mc->mode == cgltf_meshopt_compression_mode_triangles && mc->count % 3 != 0, cgltf_result_invalid_gltf);

			CGLTF_ASSERT_IF((mc->mode == cgltf_meshopt_compression_mode_triangles || mc->mode == cgltf_meshopt_compression_mode_indices) && mc->stride != 2 && mc->stride != 4, cgltf_result_invalid_gltf);

			CGLTF_ASSERT_IF((mc->mode == cgltf_meshopt_compression_mode_triangles || mc->mode == cgltf_meshopt_compression_mode_indices) && mc->filter != cgltf_meshopt_compression_filter_none, cgltf_result_invalid_gltf);

			CGLTF_ASSERT_IF(mc->filter == cgltf_meshopt_compression_filter_octahedral && mc->stride != 4 && mc->stride != 8, cgltf_result_invalid_gltf);

			CGLTF_ASSERT_IF(mc->filter == cgltf_meshopt_compression_filter_quaternion && mc->stride != 8, cgltf_result_invalid_gltf);
		}
	}

	for (cgltf_size i = 0; i < data->meshes_count; ++i)
	{
		if (data->meshes[i].weights)
		{
			CGLTF_ASSERT_IF(data->meshes[i].primitives_count && data->meshes[i].primitives[0].targets_count != data->meshes[i].weights_count, cgltf_result_invalid_gltf);
		}

		if (data->meshes[i].target_names)
		{
			CGLTF_ASSERT_IF(data->meshes[i].primitives_count && data->meshes[i].primitives[0].targets_count != data->meshes[i].target_names_count, cgltf_result_invalid_gltf);
		}

		for (cgltf_size j = 0; j < data->meshes[i].primitives_count; ++j)
		{
			CGLTF_ASSERT_IF(data->meshes[i].primitives[j].targets_count != data->meshes[i].primitives[0].targets_count, cgltf_result_invalid_gltf);

			if (data->meshes[i].primitives[j].attributes_count)
			{
				cgltf_accessor* first = data->meshes[i].primitives[j].attributes[0].data;

				for (cgltf_size k = 0; k < data->meshes[i].primitives[j].attributes_count; ++k)
				{
					CGLTF_ASSERT_IF(data->meshes[i].primitives[j].attributes[k].data->count != first->count, cgltf_result_invalid_gltf);
				}

				for (cgltf_size k = 0; k < data->meshes[i].primitives[j].targets_count; ++k)
				{
					for (cgltf_size m = 0; m < data->meshes[i].primitives[j].targets[k].attributes_count; ++m)
					{
						CGLTF_ASSERT_IF(data->meshes[i].primitives[j].targets[k].attributes[m].data->count != first->count, cgltf_result_invalid_gltf);
					}
				}

				cgltf_accessor* indices = data->meshes[i].primitives[j].indices;

				CGLTF_ASSERT_IF(indices &&
					indices->component_type != cgltf_component_type_r_8u &&
					indices->component_type != cgltf_component_type_r_16u &&
					indices->component_type != cgltf_component_type_r_32u, cgltf_result_invalid_gltf);

				if (indices && indices->buffer_view && indices->buffer_view->buffer->data)
				{
					cgltf_size index_bound = cgltf_calc_index_bound(indices->buffer_view, indices->offset, indices->component_type, indices->count);

					CGLTF_ASSERT_IF(index_bound >= first->count, cgltf_result_data_too_short);
				}

				for (cgltf_size k = 0; k < data->meshes[i].primitives[j].mappings_count; ++k)
				{
					CGLTF_ASSERT_IF(data->meshes[i].primitives[j].mappings[k].variant >= data->variants_count, cgltf_result_invalid_gltf);
				}
			}
		}
	}

	for (cgltf_size i = 0; i < data->nodes_count; ++i)
	{
		if (data->nodes[i].weights && data->nodes[i].mesh)
		{
			CGLTF_ASSERT_IF (data->nodes[i].mesh->primitives_count && data->nodes[i].mesh->primitives[0].targets_count != data->nodes[i].weights_count, cgltf_result_invalid_gltf);
		}
	}

	for (cgltf_size i = 0; i < data->nodes_count; ++i)
	{
		cgltf_node* p1 = data->nodes[i].parent;
		cgltf_node* p2 = p1 ? p1->parent : NULL;

		while (p1 && p2)
		{
			CGLTF_ASSERT_IF(p1 == p2, cgltf_result_invalid_gltf);

			p1 = p1->parent;
			p2 = p2->parent ? p2->parent->parent : NULL;
		}
	}

	for (cgltf_size i = 0; i < data->scenes_count; ++i)
	{
		for (cgltf_size j = 0; j < data->scenes[i].nodes_count; ++j)
		{
			CGLTF_ASSERT_IF(data->scenes[i].nodes[j]->parent, cgltf_result_invalid_gltf);
		}
	}

	for (cgltf_size i = 0; i < data->animations_count; ++i)
	{
		for (cgltf_size j = 0; j < data->animations[i].channels_count; ++j)
		{
			cgltf_animation_channel* channel = &data->animations[i].channels[j];

			if (!channel->target_node)
			{
				continue;
			}

			cgltf_size components = 1;

			if (channel->target_path == cgltf_animation_path_type_weights)
			{
				CGLTF_ASSERT_IF(!channel->target_node->mesh || !channel->target_node->mesh->primitives_count, cgltf_result_invalid_gltf);

				components = channel->target_node->mesh->primitives[0].targets_count;
			}

			cgltf_size values = channel->sampler->interpolation == cgltf_interpolation_type_cubic_spline ? 3 : 1;

			CGLTF_ASSERT_IF(channel->sampler->input->count * components * values != channel->sampler->output->count, cgltf_result_data_too_short);
		}
	}

	return cgltf_result_success;
}

cgltf_result cgltf_copy_extras_json(const cgltf_data* data, const cgltf_extras* extras, char* dest, cgltf_size* dest_size)
{
	cgltf_size json_size = extras->end_offset - extras->start_offset;

	if (!dest)
	{
		if (dest_size)
		{
			*dest_size = json_size + 1;
			return cgltf_result_success;
		}
		return cgltf_result_invalid_options;
	}

	if (*dest_size + 1 < json_size)
	{
		strncpy(dest, data->json + extras->start_offset, *dest_size - 1);
		dest[*dest_size - 1] = 0;
	}
	else
	{
		strncpy(dest, data->json + extras->start_offset, json_size);
		dest[json_size] = 0;
	}

	return cgltf_result_success;
}

void cgltf_free_extensions(cgltf_data* data, cgltf_extension* extensions, cgltf_size extensions_count)
{
	for (cgltf_size i = 0; i < extensions_count; ++i)
	{
		data->memory.free(data->memory.user_data, extensions[i].name);
		data->memory.free(data->memory.user_data, extensions[i].data);
	}
	data->memory.free(data->memory.user_data, extensions);
}

void cgltf_free(cgltf_data* data)
{
	if (!data)
	{
		return;
	}

	void (*file_release)(const struct cgltf_memory_options*, const struct cgltf_file_options*, void* data) = data->file.release ? data->file.release : cgltf_default_file_release;

	data->memory.free(data->memory.user_data, data->asset.copyright);
	data->memory.free(data->memory.user_data, data->asset.generator);
	data->memory.free(data->memory.user_data, data->asset.version);
	data->memory.free(data->memory.user_data, data->asset.min_version);

	cgltf_free_extensions(data, data->asset.extensions, data->asset.extensions_count);

	for (cgltf_size i = 0; i < data->accessors_count; ++i)
	{
		data->memory.free(data->memory.user_data, data->accessors[i].name);

		if(data->accessors[i].is_sparse)
		{
			cgltf_free_extensions(data, data->accessors[i].sparse.extensions, data->accessors[i].sparse.extensions_count);
			cgltf_free_extensions(data, data->accessors[i].sparse.indices_extensions, data->accessors[i].sparse.indices_extensions_count);
			cgltf_free_extensions(data, data->accessors[i].sparse.values_extensions, data->accessors[i].sparse.values_extensions_count);
		}
		cgltf_free_extensions(data, data->accessors[i].extensions, data->accessors[i].extensions_count);
	}
	data->memory.free(data->memory.user_data, data->accessors);

	for (cgltf_size i = 0; i < data->buffer_views_count; ++i)
	{
		data->memory.free(data->memory.user_data, data->buffer_views[i].name);
		data->memory.free(data->memory.user_data, data->buffer_views[i].data);

		cgltf_free_extensions(data, data->buffer_views[i].extensions, data->buffer_views[i].extensions_count);
	}
	data->memory.free(data->memory.user_data, data->buffer_views);

	for (cgltf_size i = 0; i < data->buffers_count; ++i)
	{
		data->memory.free(data->memory.user_data, data->buffers[i].name);

		if (data->buffers[i].data != data->bin)
		{
			file_release(&data->memory, &data->file, data->buffers[i].data);
		}
		data->memory.free(data->memory.user_data, data->buffers[i].uri);

		cgltf_free_extensions(data, data->buffers[i].extensions, data->buffers[i].extensions_count);
	}

	data->memory.free(data->memory.user_data, data->buffers);

	for (cgltf_size i = 0; i < data->meshes_count; ++i)
	{
		data->memory.free(data->memory.user_data, data->meshes[i].name);

		for (cgltf_size j = 0; j < data->meshes[i].primitives_count; ++j)
		{
			for (cgltf_size k = 0; k < data->meshes[i].primitives[j].attributes_count; ++k)
			{
				data->memory.free(data->memory.user_data, data->meshes[i].primitives[j].attributes[k].name);
			}

			data->memory.free(data->memory.user_data, data->meshes[i].primitives[j].attributes);

			for (cgltf_size k = 0; k < data->meshes[i].primitives[j].targets_count; ++k)
			{
				for (cgltf_size m = 0; m < data->meshes[i].primitives[j].targets[k].attributes_count; ++m)
				{
					data->memory.free(data->memory.user_data, data->meshes[i].primitives[j].targets[k].attributes[m].name);
				}

				data->memory.free(data->memory.user_data, data->meshes[i].primitives[j].targets[k].attributes);
			}

			data->memory.free(data->memory.user_data, data->meshes[i].primitives[j].targets);

			if (data->meshes[i].primitives[j].has_draco_mesh_compression)
			{
				for (cgltf_size k = 0; k < data->meshes[i].primitives[j].draco_mesh_compression.attributes_count; ++k)
				{
					data->memory.free(data->memory.user_data, data->meshes[i].primitives[j].draco_mesh_compression.attributes[k].name);
				}

				data->memory.free(data->memory.user_data, data->meshes[i].primitives[j].draco_mesh_compression.attributes);
			}

			data->memory.free(data->memory.user_data, data->meshes[i].primitives[j].mappings);

			cgltf_free_extensions(data, data->meshes[i].primitives[j].extensions, data->meshes[i].primitives[j].extensions_count);
		}

		data->memory.free(data->memory.user_data, data->meshes[i].primitives);
		data->memory.free(data->memory.user_data, data->meshes[i].weights);

		for (cgltf_size j = 0; j < data->meshes[i].target_names_count; ++j)
		{
			data->memory.free(data->memory.user_data, data->meshes[i].target_names[j]);
		}

		cgltf_free_extensions(data, data->meshes[i].extensions, data->meshes[i].extensions_count);

		data->memory.free(data->memory.user_data, data->meshes[i].target_names);
	}

	data->memory.free(data->memory.user_data, data->meshes);

	for (cgltf_size i = 0; i < data->materials_count; ++i)
	{
		data->memory.free(data->memory.user_data, data->materials[i].name);

		if(data->materials[i].has_pbr_metallic_roughness)
		{
			cgltf_free_extensions(data, data->materials[i].pbr_metallic_roughness.metallic_roughness_texture.extensions, data->materials[i].pbr_metallic_roughness.metallic_roughness_texture.extensions_count);
			cgltf_free_extensions(data, data->materials[i].pbr_metallic_roughness.base_color_texture.extensions, data->materials[i].pbr_metallic_roughness.base_color_texture.extensions_count);
		}
		if(data->materials[i].has_pbr_specular_glossiness)
		{
			cgltf_free_extensions(data, data->materials[i].pbr_specular_glossiness.diffuse_texture.extensions, data->materials[i].pbr_specular_glossiness.diffuse_texture.extensions_count);
			cgltf_free_extensions(data, data->materials[i].pbr_specular_glossiness.specular_glossiness_texture.extensions, data->materials[i].pbr_specular_glossiness.specular_glossiness_texture.extensions_count);
		}
		if(data->materials[i].has_clearcoat)
		{
			cgltf_free_extensions(data, data->materials[i].clearcoat.clearcoat_texture.extensions, data->materials[i].clearcoat.clearcoat_texture.extensions_count);
			cgltf_free_extensions(data, data->materials[i].clearcoat.clearcoat_roughness_texture.extensions, data->materials[i].clearcoat.clearcoat_roughness_texture.extensions_count);
			cgltf_free_extensions(data, data->materials[i].clearcoat.clearcoat_normal_texture.extensions, data->materials[i].clearcoat.clearcoat_normal_texture.extensions_count);
		}
		if(data->materials[i].has_specular)
		{
			cgltf_free_extensions(data, data->materials[i].specular.specular_texture.extensions, data->materials[i].specular.specular_texture.extensions_count);
			cgltf_free_extensions(data, data->materials[i].specular.specular_color_texture.extensions, data->materials[i].specular.specular_color_texture.extensions_count);
		}
		if(data->materials[i].has_transmission)
		{
			cgltf_free_extensions(data, data->materials[i].transmission.transmission_texture.extensions, data->materials[i].transmission.transmission_texture.extensions_count);
		}
		if (data->materials[i].has_volume)
		{
			cgltf_free_extensions(data, data->materials[i].volume.thickness_texture.extensions, data->materials[i].volume.thickness_texture.extensions_count);
		}
		if(data->materials[i].has_sheen)
		{
			cgltf_free_extensions(data, data->materials[i].sheen.sheen_color_texture.extensions, data->materials[i].sheen.sheen_color_texture.extensions_count);
			cgltf_free_extensions(data, data->materials[i].sheen.sheen_roughness_texture.extensions, data->materials[i].sheen.sheen_roughness_texture.extensions_count);
		}

		cgltf_free_extensions(data, data->materials[i].normal_texture.extensions, data->materials[i].normal_texture.extensions_count);
		cgltf_free_extensions(data, data->materials[i].occlusion_texture.extensions, data->materials[i].occlusion_texture.extensions_count);
		cgltf_free_extensions(data, data->materials[i].emissive_texture.extensions, data->materials[i].emissive_texture.extensions_count);

		cgltf_free_extensions(data, data->materials[i].extensions, data->materials[i].extensions_count);
	}

	data->memory.free(data->memory.user_data, data->materials);

	for (cgltf_size i = 0; i < data->images_count; ++i) 
	{
		data->memory.free(data->memory.user_data, data->images[i].name);
		data->memory.free(data->memory.user_data, data->images[i].uri);
		data->memory.free(data->memory.user_data, data->images[i].mime_type);

		cgltf_free_extensions(data, data->images[i].extensions, data->images[i].extensions_count);
	}

	data->memory.free(data->memory.user_data, data->images);

	for (cgltf_size i = 0; i < data->textures_count; ++i)
	{
		data->memory.free(data->memory.user_data, data->textures[i].name);
		cgltf_free_extensions(data, data->textures[i].extensions, data->textures[i].extensions_count);
	}

	data->memory.free(data->memory.user_data, data->textures);

	for (cgltf_size i = 0; i < data->samplers_count; ++i)
	{
		data->memory.free(data->memory.user_data, data->samplers[i].name);
		cgltf_free_extensions(data, data->samplers[i].extensions, data->samplers[i].extensions_count);
	}

	data->memory.free(data->memory.user_data, data->samplers);

	for (cgltf_size i = 0; i < data->skins_count; ++i)
	{
		data->memory.free(data->memory.user_data, data->skins[i].name);
		data->memory.free(data->memory.user_data, data->skins[i].joints);

		cgltf_free_extensions(data, data->skins[i].extensions, data->skins[i].extensions_count);
	}

	data->memory.free(data->memory.user_data, data->skins);

	for (cgltf_size i = 0; i < data->cameras_count; ++i)
	{
		data->memory.free(data->memory.user_data, data->cameras[i].name);
		cgltf_free_extensions(data, data->cameras[i].extensions, data->cameras[i].extensions_count);
	}

	data->memory.free(data->memory.user_data, data->cameras);

	for (cgltf_size i = 0; i < data->lights_count; ++i)
	{
		data->memory.free(data->memory.user_data, data->lights[i].name);
	}

	data->memory.free(data->memory.user_data, data->lights);

	for (cgltf_size i = 0; i < data->nodes_count; ++i)
	{
		data->memory.free(data->memory.user_data, data->nodes[i].name);
		data->memory.free(data->memory.user_data, data->nodes[i].children);
		data->memory.free(data->memory.user_data, data->nodes[i].weights);
		cgltf_free_extensions(data, data->nodes[i].extensions, data->nodes[i].extensions_count);
	}

	data->memory.free(data->memory.user_data, data->nodes);

	for (cgltf_size i = 0; i < data->scenes_count; ++i)
	{
		data->memory.free(data->memory.user_data, data->scenes[i].name);
		data->memory.free(data->memory.user_data, data->scenes[i].nodes);

		cgltf_free_extensions(data, data->scenes[i].extensions, data->scenes[i].extensions_count);
	}

	data->memory.free(data->memory.user_data, data->scenes);

	for (cgltf_size i = 0; i < data->animations_count; ++i)
	{
		data->memory.free(data->memory.user_data, data->animations[i].name);
		for (cgltf_size j = 0; j <  data->animations[i].samplers_count; ++j)
		{
			cgltf_free_extensions(data, data->animations[i].samplers[j].extensions, data->animations[i].samplers[j].extensions_count);
		}
		data->memory.free(data->memory.user_data, data->animations[i].samplers);

		for (cgltf_size j = 0; j <  data->animations[i].channels_count; ++j)
		{
			cgltf_free_extensions(data, data->animations[i].channels[j].extensions, data->animations[i].channels[j].extensions_count);
		}
		data->memory.free(data->memory.user_data, data->animations[i].channels);

		cgltf_free_extensions(data, data->animations[i].extensions, data->animations[i].extensions_count);
	}

	data->memory.free(data->memory.user_data, data->animations);

	for (cgltf_size i = 0; i < data->variants_count; ++i)
	{
		data->memory.free(data->memory.user_data, data->variants[i].name);
	}

	data->memory.free(data->memory.user_data, data->variants);

	cgltf_free_extensions(data, data->data_extensions, data->data_extensions_count);

	for (cgltf_size i = 0; i < data->extensions_used_count; ++i)
	{
		data->memory.free(data->memory.user_data, data->extensions_used[i]);
	}

	data->memory.free(data->memory.user_data, data->extensions_used);

	for (cgltf_size i = 0; i < data->extensions_required_count; ++i)
	{
		data->memory.free(data->memory.user_data, data->extensions_required[i]);
	}

	data->memory.free(data->memory.user_data, data->extensions_required);

	file_release(&data->memory, &data->file, data->file_data);

	data->memory.free(data->memory.user_data, data);
}

void cgltf_node_transform_local(const cgltf_node* node, cgltf_float* out_matrix)
{
	cgltf_float* lm = out_matrix;

	if (node->has_matrix)
	{
		memcpy(lm, node->matrix, sizeof(float) * 16);
	}
	else
	{
		float tx = node->translation[0];
		float ty = node->translation[1];
		float tz = node->translation[2];

		float qx = node->rotation[0];
		float qy = node->rotation[1];
		float qz = node->rotation[2];
		float qw = node->rotation[3];

		float sx = node->scale[0];
		float sy = node->scale[1];
		float sz = node->scale[2];

		lm[0] = (1 - 2 * qy*qy - 2 * qz*qz) * sx;
		lm[1] = (2 * qx*qy + 2 * qz*qw) * sx;
		lm[2] = (2 * qx*qz - 2 * qy*qw) * sx;
		lm[3] = 0.f;

		lm[4] = (2 * qx*qy - 2 * qz*qw) * sy;
		lm[5] = (1 - 2 * qx*qx - 2 * qz*qz) * sy;
		lm[6] = (2 * qy*qz + 2 * qx*qw) * sy;
		lm[7] = 0.f;

		lm[8] = (2 * qx*qz + 2 * qy*qw) * sz;
		lm[9] = (2 * qy*qz - 2 * qx*qw) * sz;
		lm[10] = (1 - 2 * qx*qx - 2 * qy*qy) * sz;
		lm[11] = 0.f;

		lm[12] = tx;
		lm[13] = ty;
		lm[14] = tz;
		lm[15] = 1.f;
	}
}

void cgltf_node_transform_world(const cgltf_node* node, cgltf_float* out_matrix)
{
	cgltf_float* lm = out_matrix;
	cgltf_node_transform_local(node, lm);

	const cgltf_node* parent = node->parent;

	while (parent)
	{
		float pm[16];
		cgltf_node_transform_local(parent, pm);

		for (int i = 0; i < 4; ++i)
		{
			float l0 = lm[i * 4 + 0];
			float l1 = lm[i * 4 + 1];
			float l2 = lm[i * 4 + 2];

			float r0 = l0 * pm[0] + l1 * pm[4] + l2 * pm[8];
			float r1 = l0 * pm[1] + l1 * pm[5] + l2 * pm[9];
			float r2 = l0 * pm[2] + l1 * pm[6] + l2 * pm[10];

			lm[i * 4 + 0] = r0;
			lm[i * 4 + 1] = r1;
			lm[i * 4 + 2] = r2;
		}

		lm[12] += pm[12];
		lm[13] += pm[13];
		lm[14] += pm[14];

		parent = parent->parent;
	}
}

cgltf_size cgltf_component_read_index(const void* in, cgltf_component_type component_type)
{
	switch (component_type)
	{
		case cgltf_component_type_r_16:
			return *((const int16_t*) in);
		case cgltf_component_type_r_16u:
			return *((const uint16_t*) in);
		case cgltf_component_type_r_32u:
			return *((const uint32_t*) in);
		case cgltf_component_type_r_32f:
			return (cgltf_size)*((const float*) in);
		case cgltf_component_type_r_8:
			return *((const int8_t*) in);
		case cgltf_component_type_r_8u:
			return *((const uint8_t*) in);
		default:
			return 0;
	}
}

cgltf_float cgltf_component_read_float(const void* in, cgltf_component_type component_type, cgltf_bool normalized)
{
	if (component_type == cgltf_component_type_r_32f)
	{
		return *((const float*) in);
	}

	if (normalized)
	{
		switch (component_type)
		{
			// note: glTF spec doesn't currently define normalized conversions for 32-bit integers
			case cgltf_component_type_r_16:
				return *((const int16_t*) in) / (cgltf_float)32767;
			case cgltf_component_type_r_16u:
				return *((const uint16_t*) in) / (cgltf_float)65535;
			case cgltf_component_type_r_8:
				return *((const int8_t*) in) / (cgltf_float)127;
			case cgltf_component_type_r_8u:
				return *((const uint8_t*) in) / (cgltf_float)255;
			default:
				return 0;
		}
	}

	return (cgltf_float)cgltf_component_read_index(in, component_type);
}

cgltf_bool cgltf_element_read_float(const uint8_t* element, cgltf_type type, cgltf_component_type component_type, cgltf_bool normalized, cgltf_float* out, cgltf_size element_size)
{
	cgltf_size num_components = cgltf_num_components(type);

	if (element_size < num_components) {
		return 0;
	}

	// There are three special cases for component extraction, see #data-alignment in the 2.0 spec.

	cgltf_size component_size = cgltf_component_size(component_type);

	if (type == cgltf_type_mat2 && component_size == 1)
	{
		out[0] = cgltf_component_read_float(element, component_type, normalized);
		out[1] = cgltf_component_read_float(element + 1, component_type, normalized);
		out[2] = cgltf_component_read_float(element + 4, component_type, normalized);
		out[3] = cgltf_component_read_float(element + 5, component_type, normalized);
		return 1;
	}

	if (type == cgltf_type_mat3 && component_size == 1)
	{
		out[0] = cgltf_component_read_float(element, component_type, normalized);
		out[1] = cgltf_component_read_float(element + 1, component_type, normalized);
		out[2] = cgltf_component_read_float(element + 2, component_type, normalized);
		out[3] = cgltf_component_read_float(element + 4, component_type, normalized);
		out[4] = cgltf_component_read_float(element + 5, component_type, normalized);
		out[5] = cgltf_component_read_float(element + 6, component_type, normalized);
		out[6] = cgltf_component_read_float(element + 8, component_type, normalized);
		out[7] = cgltf_component_read_float(element + 9, component_type, normalized);
		out[8] = cgltf_component_read_float(element + 10, component_type, normalized);
		return 1;
	}

	if (type == cgltf_type_mat3 && component_size == 2)
	{
		out[0] = cgltf_component_read_float(element, component_type, normalized);
		out[1] = cgltf_component_read_float(element + 2, component_type, normalized);
		out[2] = cgltf_component_read_float(element + 4, component_type, normalized);
		out[3] = cgltf_component_read_float(element + 8, component_type, normalized);
		out[4] = cgltf_component_read_float(element + 10, component_type, normalized);
		out[5] = cgltf_component_read_float(element + 12, component_type, normalized);
		out[6] = cgltf_component_read_float(element + 16, component_type, normalized);
		out[7] = cgltf_component_read_float(element + 18, component_type, normalized);
		out[8] = cgltf_component_read_float(element + 20, component_type, normalized);
		return 1;
	}

	for (cgltf_size i = 0; i < num_components; ++i)
	{
		out[i] = cgltf_component_read_float(element + component_size * i, component_type, normalized);
	}
	return 1;
}

const uint8_t* cgltf_buffer_view_data(const cgltf_buffer_view* view)
{
	if (view->data)
		return (const uint8_t*)view->data;

	if (!view->buffer->data)
		return NULL;

	const uint8_t* result = (const uint8_t*)view->buffer->data;
	result += view->offset;
	return result;
}

cgltf_bool cgltf_accessor_read_float(const cgltf_accessor* accessor, cgltf_size index, cgltf_float* out, cgltf_size element_size)
{
	if (accessor->is_sparse)
	{
		return 0;
	}
	if (accessor->buffer_view == NULL)
	{
		memset(out, 0, element_size * sizeof(cgltf_float));
		return 1;
	}
	const uint8_t* element = cgltf_buffer_view_data(accessor->buffer_view);
	if (element == NULL)
	{
		return 0;
	}
	element += accessor->offset + accessor->stride * index;
	return cgltf_element_read_float(element, accessor->type, accessor->component_type, accessor->normalized, out, element_size);
}

cgltf_size cgltf_accessor_unpack_floats(const cgltf_accessor* accessor, cgltf_float* out, cgltf_size float_count)
{
	cgltf_size floats_per_element = cgltf_num_components(accessor->type);
	cgltf_size available_floats = accessor->count * floats_per_element;
	if (out == NULL)
	{
		return available_floats;
	}

	float_count = available_floats < float_count ? available_floats : float_count;
	cgltf_size element_count = float_count / floats_per_element;

	// First pass: convert each element in the base accessor.
	cgltf_float* dest = out;
	cgltf_accessor dense = *accessor;
	dense.is_sparse = 0;
	for (cgltf_size index = 0; index < element_count; index++, dest += floats_per_element)
	{
		if (!cgltf_accessor_read_float(&dense, index, dest, floats_per_element))
		{
			return 0;
		}
	}

	// Second pass: write out each element in the sparse accessor.
	if (accessor->is_sparse)
	{
		const cgltf_accessor_sparse* sparse = &dense.sparse;

		const uint8_t* index_data = cgltf_buffer_view_data(sparse->indices_buffer_view);
		const uint8_t* reader_head = cgltf_buffer_view_data(sparse->values_buffer_view);

		if (index_data == NULL || reader_head == NULL)
		{
			return 0;
		}

		index_data += sparse->indices_byte_offset;
		reader_head += sparse->values_byte_offset;

		cgltf_size index_stride = cgltf_component_size(sparse->indices_component_type);
		for (cgltf_size reader_index = 0; reader_index < sparse->count; reader_index++, index_data += index_stride)
		{
			size_t writer_index = cgltf_component_read_index(index_data, sparse->indices_component_type);
			float* writer_head = out + writer_index * floats_per_element;

			if (!cgltf_element_read_float(reader_head, dense.type, dense.component_type, dense.normalized, writer_head, floats_per_element))
			{
				return 0;
			}

			reader_head += dense.stride;
		}
	}

	return element_count * floats_per_element;
}

cgltf_uint cgltf_component_read_uint(const void* in, cgltf_component_type component_type)
{
	switch (component_type)
	{
		case cgltf_component_type_r_8:
			return *((const int8_t*) in);

		case cgltf_component_type_r_8u:
			return *((const uint8_t*) in);

		case cgltf_component_type_r_16:
			return *((const int16_t*) in);

		case cgltf_component_type_r_16u:
			return *((const uint16_t*) in);

		case cgltf_component_type_r_32u:
			return *((const uint32_t*) in);

		default:
			return 0;
	}
}

cgltf_bool cgltf_element_read_uint(const uint8_t* element, cgltf_type type, cgltf_component_type component_type, cgltf_uint* out, cgltf_size element_size)
{
	cgltf_size num_components = cgltf_num_components(type);

	if (element_size < num_components)
	{
		return 0;
	}

	// Reading integer matrices is not a valid use case
	if (type == cgltf_type_mat2 || type == cgltf_type_mat3 || type == cgltf_type_mat4)
	{
		return 0;
	}

	cgltf_size component_size = cgltf_component_size(component_type);

	for (cgltf_size i = 0; i < num_components; ++i)
	{
		out[i] = cgltf_component_read_uint(element + component_size * i, component_type);
	}
	return 1;
}

cgltf_bool cgltf_accessor_read_uint(const cgltf_accessor* accessor, cgltf_size index, cgltf_uint* out, cgltf_size element_size)
{
	if (accessor->is_sparse)
	{
		return 0;
	}
	if (accessor->buffer_view == NULL)
	{
		memset(out, 0, element_size * sizeof( cgltf_uint ));
		return 1;
	}
	const uint8_t* element = cgltf_buffer_view_data(accessor->buffer_view);
	if (element == NULL)
	{
		return 0;
	}
	element += accessor->offset + accessor->stride * index;
	return cgltf_element_read_uint(element, accessor->type, accessor->component_type, out, element_size);
}

cgltf_size cgltf_accessor_read_index(const cgltf_accessor* accessor, cgltf_size index)
{
	if (accessor->is_sparse)
	{
		return 0; // This is an error case, but we can't communicate the error with existing interface.
	}
	if (accessor->buffer_view == NULL)
	{
		return 0;
	}
	const uint8_t* element = cgltf_buffer_view_data(accessor->buffer_view);
	if (element == NULL)
	{
		return 0; // This is an error case, but we can't communicate the error with existing interface.
	}
	element += accessor->offset + accessor->stride * index;
	return cgltf_component_read_index(element, accessor->component_type);
}

int cgltf_json_strcmp(jsmntok_t const* tok, const uint8_t* json_chunk, const char* str)
{
	CGLTF_CHECK_TOKTYPE(*tok, JSMN_STRING);
	size_t const str_len = strlen(str);
	size_t const name_length = tok->end - tok->start;
	return (str_len == name_length) ? strncmp((const char*)json_chunk + tok->start, str, str_len) : 128;
}

int cgltf_json_to_int(jsmntok_t const* tok, const uint8_t* json_chunk)
{
	CGLTF_CHECK_TOKTYPE(*tok, JSMN_PRIMITIVE);
	char tmp[128];
	int size = (cgltf_size)(tok->end - tok->start) < sizeof(tmp) ? tok->end - tok->start : (int)(sizeof(tmp) - 1);
	strncpy(tmp, (const char*)json_chunk + tok->start, size);
	tmp[size] = 0;
	return CGLTF_ATOI(tmp);
}

cgltf_float cgltf_json_to_float(jsmntok_t const* tok, const uint8_t* json_chunk)
{
	CGLTF_CHECK_TOKTYPE(*tok, JSMN_PRIMITIVE);
	char tmp[128];
	int size = (cgltf_size)(tok->end - tok->start) < sizeof(tmp) ? tok->end - tok->start : (int)(sizeof(tmp) - 1);
	strncpy(tmp, (const char*)json_chunk + tok->start, size);
	tmp[size] = 0;
	return (cgltf_float)CGLTF_ATOF(tmp);
}

cgltf_bool cgltf_json_to_bool(jsmntok_t const* tok, const uint8_t* json_chunk)
{
	int size = tok->end - tok->start;
	return size == 4 && memcmp(json_chunk + tok->start, "true", 4) == 0;
}

int cgltf_skip_json(jsmntok_t const* tokens, int i)
{
	int end = i + 1;

	while (i < end)
	{
		switch (tokens[i].type)
		{
		case JSMN_OBJECT:
			end += tokens[i].size * 2;
			break;

		case JSMN_ARRAY:
			end += tokens[i].size;
			break;

		case JSMN_PRIMITIVE:
		case JSMN_STRING:
			break;

		default:
			return -1;
		}

		i++;
	}

	return i;
}

void cgltf_fill_float_array(float* out_array, int size, float value)
{
	for (int j = 0; j < size; ++j)
	{
		out_array[j] = value;
	}
}

int cgltf_parse_json_float_array(jsmntok_t const* tokens, int i, const uint8_t* json_chunk, float* out_array, int size)
{
	CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_ARRAY);
	if (tokens[i].size != size)
	{
		return CGLTF_ERROR_JSON;
	}
	++i;
	for (int j = 0; j < size; ++j)
	{
		CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_PRIMITIVE);
		out_array[j] = cgltf_json_to_float(tokens + i, json_chunk);
		++i;
	}
	return i;
}

int cgltf_parse_json_string(cgltf_options* options, jsmntok_t const* tokens, int i, const uint8_t* json_chunk, char** out_string)
{
	CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_STRING);
	if (*out_string)
	{
		return CGLTF_ERROR_JSON;
	}
	int size = tokens[i].end - tokens[i].start;
	char* result = (char*)options->memory.alloc(options->memory.user_data, size + 1);
	if (!result)
	{
		return CGLTF_ERROR_NOMEM;
	}
	strncpy(result, (const char*)json_chunk + tokens[i].start, size);
	result[size] = 0;
	*out_string = result;
	return i + 1;
}

int cgltf_parse_json_array(cgltf_options* options, jsmntok_t const* tokens, int i, const uint8_t* json_chunk, size_t element_size, void** out_array, cgltf_size* out_size)
{
	(void)json_chunk;
	if (tokens[i].type != JSMN_ARRAY)
	{
		return tokens[i].type == JSMN_OBJECT ? CGLTF_ERROR_LEGACY : CGLTF_ERROR_JSON;
	}
	if (*out_array)
	{
		return CGLTF_ERROR_JSON;
	}
	int size = tokens[i].size;
	void* result = cgltf_calloc(options, element_size, size);
	if (!result)
	{
		return CGLTF_ERROR_NOMEM;
	}
	*out_array = result;
	*out_size = size;
	return i + 1;
}

int cgltf_parse_json_string_array(cgltf_options* options, jsmntok_t const* tokens, int i, const uint8_t* json_chunk, char*** out_array, cgltf_size* out_size)
{
	CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_ARRAY);
	i = cgltf_parse_json_array(options, tokens, i, json_chunk, sizeof(char*), (void**)out_array, out_size);
	if (i < 0)
	{
		return i;
	}

	for (cgltf_size j = 0; j < *out_size; ++j)
	{
		i = cgltf_parse_json_string(options, tokens, i, json_chunk, j + (*out_array));
		if (i < 0)
		{
			return i;
		}
	}
	return i;
}

void cgltf_parse_attribute_type(const char* name, cgltf_attribute_type* out_type, int* out_index)
{
	const char* us = strchr(name, '_');
	size_t len = us ? (size_t)(us - name) : strlen(name);

	if (len == 8 && strncmp(name, "POSITION", 8) == 0)
	{
		*out_type = cgltf_attribute_type_position;
	}
	else if (len == 6 && strncmp(name, "NORMAL", 6) == 0)
	{
		*out_type = cgltf_attribute_type_normal;
	}
	else if (len == 7 && strncmp(name, "TANGENT", 7) == 0)
	{
		*out_type = cgltf_attribute_type_tangent;
	}
	else if (len == 8 && strncmp(name, "TEXCOORD", 8) == 0)
	{
		*out_type = cgltf_attribute_type_texcoord;
	}
	else if (len == 5 && strncmp(name, "COLOR", 5) == 0)
	{
		*out_type = cgltf_attribute_type_color;
	}
	else if (len == 6 && strncmp(name, "JOINTS", 6) == 0)
	{
		*out_type = cgltf_attribute_type_joints;
	}
	else if (len == 7 && strncmp(name, "WEIGHTS", 7) == 0)
	{
		*out_type = cgltf_attribute_type_weights;
	}
	else
	{
		*out_type = cgltf_attribute_type_invalid;
	}

	if (us && *out_type != cgltf_attribute_type_invalid)
	{
		*out_index = CGLTF_ATOI(us + 1);
	}
}

int cgltf_parse_json_attribute_list(cgltf_options* options, jsmntok_t const* tokens, int i, const uint8_t* json_chunk, cgltf_attribute** out_attributes, cgltf_size* out_attributes_count)
{
	CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_OBJECT);

	if (*out_attributes)
	{
		return CGLTF_ERROR_JSON;
	}

	*out_attributes_count = tokens[i].size;
	*out_attributes = (cgltf_attribute*)cgltf_calloc(options, sizeof(cgltf_attribute), *out_attributes_count);
	++i;

	if (!*out_attributes)
	{
		return CGLTF_ERROR_NOMEM;
	}

	for (cgltf_size j = 0; j < *out_attributes_count; ++j)
	{
		CGLTF_CHECK_KEY(tokens[i]);

		i = cgltf_parse_json_string(options, tokens, i, json_chunk, &(*out_attributes)[j].name);
		if (i < 0)
		{
			return CGLTF_ERROR_JSON;
		}

		cgltf_parse_attribute_type((*out_attributes)[j].name, &(*out_attributes)[j].type, &(*out_attributes)[j].index);

		(*out_attributes)[j].data = CGLTF_PTRINDEX(cgltf_accessor, cgltf_json_to_int(tokens + i, json_chunk));
		++i;
	}

	return i;
}

int cgltf_parse_json_extras(jsmntok_t const* tokens, int i, const uint8_t* json_chunk, cgltf_extras* out_extras)
{
	(void)json_chunk;
	out_extras->start_offset = tokens[i].start;
	out_extras->end_offset = tokens[i].end;
	i = cgltf_skip_json(tokens, i);
	return i;
}

int cgltf_parse_json_unprocessed_extension(cgltf_options* options, jsmntok_t const* tokens, int i, const uint8_t* json_chunk, cgltf_extension* out_extension)
{
	CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_STRING);
	CGLTF_CHECK_TOKTYPE(tokens[i+1], JSMN_OBJECT);
	if (out_extension->name)
	{
		return CGLTF_ERROR_JSON;
	}

	cgltf_size name_length = tokens[i].end - tokens[i].start;
	out_extension->name = (char*)options->memory.alloc(options->memory.user_data, name_length + 1);
	if (!out_extension->name)
	{
		return CGLTF_ERROR_NOMEM;
	}
	strncpy(out_extension->name, (const char*)json_chunk + tokens[i].start, name_length);
	out_extension->name[name_length] = 0;
	i++;

	size_t start = tokens[i].start;
	size_t size = tokens[i].end - start;
	out_extension->data = (char*)options->memory.alloc(options->memory.user_data, size + 1);
	if (!out_extension->data)
	{
		return CGLTF_ERROR_NOMEM;
	}
	strncpy(out_extension->data, (const char*)json_chunk + start, size);
	out_extension->data[size] = '\0';

	i = cgltf_skip_json(tokens, i);

	return i;
}

int cgltf_parse_json_unprocessed_extensions(cgltf_options* options, jsmntok_t const* tokens, int i, const uint8_t* json_chunk, cgltf_size* out_extensions_count, cgltf_extension** out_extensions)
{
	++i;

	CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_OBJECT);
	if(*out_extensions)
	{
		return CGLTF_ERROR_JSON;
	}

	int extensions_size = tokens[i].size;
	*out_extensions_count = 0;
	*out_extensions = (cgltf_extension*)cgltf_calloc(options, sizeof(cgltf_extension), extensions_size);

	if (!*out_extensions)
	{
		return CGLTF_ERROR_NOMEM;
	}

	++i;

	for (int j = 0; j < extensions_size; ++j)
	{
		CGLTF_CHECK_KEY(tokens[i]);

		cgltf_size extension_index = (*out_extensions_count)++;
		cgltf_extension* extension = &((*out_extensions)[extension_index]);
		i = cgltf_parse_json_unprocessed_extension(options, tokens, i, json_chunk, extension);

		if (i < 0)
		{
			return i;
		}
	}
	return i;
}

int cgltf_parse_json_draco_mesh_compression(cgltf_options* options, jsmntok_t const* tokens, int i, const uint8_t* json_chunk, cgltf_draco_mesh_compression* out_draco_mesh_compression)
{
	CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_OBJECT);

	int size = tokens[i].size;
	++i;

	for (int j = 0; j < size; ++j)
	{
		CGLTF_CHECK_KEY(tokens[i]);

		if (cgltf_json_strcmp(tokens + i, json_chunk, "attributes") == 0)
		{
			i = cgltf_parse_json_attribute_list(options, tokens, i + 1, json_chunk, &out_draco_mesh_compression->attributes, &out_draco_mesh_compression->attributes_count);
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "bufferView") == 0)
		{
			++i;
			out_draco_mesh_compression->buffer_view = CGLTF_PTRINDEX(cgltf_buffer_view, cgltf_json_to_int(tokens + i, json_chunk));
			++i;
		}

		if (i < 0)
		{
			return i;
		}
	}

	return i;
}

int cgltf_parse_json_material_mapping_data(cgltf_options* options, jsmntok_t const* tokens, int i, const uint8_t* json_chunk, cgltf_material_mapping* out_mappings, cgltf_size* offset)
{
	(void)options;
	CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_ARRAY);

	int size = tokens[i].size;
	++i;

	for (int j = 0; j < size; ++j)
	{
		CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_OBJECT);

		int obj_size = tokens[i].size;
		++i;

		int material = -1;
		int variants_tok = -1;
		cgltf_extras extras = {0, 0};

		for (int k = 0; k < obj_size; ++k)
		{
			CGLTF_CHECK_KEY(tokens[i]);

			if (cgltf_json_strcmp(tokens + i, json_chunk, "material") == 0)
			{
				++i;
				material = cgltf_json_to_int(tokens + i, json_chunk);
				++i;
			}
			else if (cgltf_json_strcmp(tokens + i, json_chunk, "variants") == 0)
			{
				variants_tok = i+1;
				CGLTF_CHECK_TOKTYPE(tokens[variants_tok], JSMN_ARRAY);

				i = cgltf_skip_json(tokens, i+1);
			}
			else if (cgltf_json_strcmp(tokens + i, json_chunk, "extras") == 0)
			{
				i = cgltf_parse_json_extras(tokens, i + 1, json_chunk, &extras);
			}
			else
			{
				i = cgltf_skip_json(tokens, i+1);
			}

			if (i < 0)
			{
				return i;
			}
		}

		if (material < 0 || variants_tok < 0)
		{
			return CGLTF_ERROR_JSON;
		}

		if (out_mappings)
		{
			for (int k = 0; k < tokens[variants_tok].size; ++k)
			{
				int variant = cgltf_json_to_int(&tokens[variants_tok + 1 + k], json_chunk);
				if (variant < 0)
					return variant;

				out_mappings[*offset].material = CGLTF_PTRINDEX(cgltf_material, material);
				out_mappings[*offset].variant = variant;
				out_mappings[*offset].extras = extras;

				(*offset)++;
			}
		}
		else
		{
			(*offset) += tokens[variants_tok].size;
		}
	}

	return i;
}

int cgltf_parse_json_material_mappings(cgltf_options* options, jsmntok_t const* tokens, int i, const uint8_t* json_chunk, cgltf_primitive* out_prim)
{
	CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_OBJECT);

	int size = tokens[i].size;
	++i;

	for (int j = 0; j < size; ++j)
	{
		CGLTF_CHECK_KEY(tokens[i]);

		if (cgltf_json_strcmp(tokens + i, json_chunk, "mappings") == 0)
		{
			if (out_prim->mappings)
			{
				return CGLTF_ERROR_JSON;
			}

			cgltf_size mappings_offset = 0;
			int k = cgltf_parse_json_material_mapping_data(options, tokens, i + 1, json_chunk, NULL, &mappings_offset);
			if (k < 0)
			{
				return k;
			}

			out_prim->mappings_count = mappings_offset;
			out_prim->mappings = (cgltf_material_mapping*)cgltf_calloc(options, sizeof(cgltf_material_mapping), out_prim->mappings_count);

			mappings_offset = 0;
			i = cgltf_parse_json_material_mapping_data(options, tokens, i + 1, json_chunk, out_prim->mappings, &mappings_offset);
		}
		else
		{
			i = cgltf_skip_json(tokens, i+1);
		}

		if (i < 0)
		{
			return i;
		}
	}

	return i;
}

int cgltf_parse_json_primitive(cgltf_options* options, jsmntok_t const* tokens, int i, const uint8_t* json_chunk, cgltf_primitive* out_prim)
{
	CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_OBJECT);

	out_prim->type = cgltf_primitive_type_triangles;

	int size = tokens[i].size;
	++i;

	for (int j = 0; j < size; ++j)
	{
		CGLTF_CHECK_KEY(tokens[i]);

		if (cgltf_json_strcmp(tokens+i, json_chunk, "mode") == 0)
		{
			++i;
			out_prim->type
					= (cgltf_primitive_type)
					cgltf_json_to_int(tokens+i, json_chunk);
			++i;
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "indices") == 0)
		{
			++i;
			out_prim->indices = CGLTF_PTRINDEX(cgltf_accessor, cgltf_json_to_int(tokens + i, json_chunk));
			++i;
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "material") == 0)
		{
			++i;
			out_prim->material = CGLTF_PTRINDEX(cgltf_material, cgltf_json_to_int(tokens + i, json_chunk));
			++i;
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "attributes") == 0)
		{
			i = cgltf_parse_json_attribute_list(options, tokens, i + 1, json_chunk, &out_prim->attributes, &out_prim->attributes_count);
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "targets") == 0)
		{
			i = cgltf_parse_json_array(options, tokens, i + 1, json_chunk, sizeof(cgltf_morph_target), (void**)&out_prim->targets, &out_prim->targets_count);
			if (i < 0)
			{
				return i;
			}

			for (cgltf_size k = 0; k < out_prim->targets_count; ++k)
			{
				i = cgltf_parse_json_attribute_list(options, tokens, i, json_chunk, &out_prim->targets[k].attributes, &out_prim->targets[k].attributes_count);
				if (i < 0)
				{
					return i;
				}
			}
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "extras") == 0)
		{
			i = cgltf_parse_json_extras(tokens, i + 1, json_chunk, &out_prim->extras);
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "extensions") == 0)
		{
			++i;

			CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_OBJECT);
			if(out_prim->extensions)
			{
				return CGLTF_ERROR_JSON;
			}

			int extensions_size = tokens[i].size;
			out_prim->extensions_count = 0;
			out_prim->extensions = (cgltf_extension*)cgltf_calloc(options, sizeof(cgltf_extension), extensions_size);

			if (!out_prim->extensions)
			{
				return CGLTF_ERROR_NOMEM;
			}

			++i;
			for (int k = 0; k < extensions_size; ++k)
			{
				CGLTF_CHECK_KEY(tokens[i]);

				if (cgltf_json_strcmp(tokens+i, json_chunk, "KHR_draco_mesh_compression") == 0)
				{
					out_prim->has_draco_mesh_compression = 1;
					i = cgltf_parse_json_draco_mesh_compression(options, tokens, i + 1, json_chunk, &out_prim->draco_mesh_compression);
				}
				else if (cgltf_json_strcmp(tokens+i, json_chunk, "KHR_materials_variants") == 0)
				{
					i = cgltf_parse_json_material_mappings(options, tokens, i + 1, json_chunk, out_prim);
				}
				else
				{
					i = cgltf_parse_json_unprocessed_extension(options, tokens, i, json_chunk, &(out_prim->extensions[out_prim->extensions_count++]));
				}

				if (i < 0)
				{
					return i;
				}
			}
		}
		else
		{
			i = cgltf_skip_json(tokens, i+1);
		}

		if (i < 0)
		{
			return i;
		}
	}

	return i;
}

int cgltf_parse_json_mesh(cgltf_options* options, jsmntok_t const* tokens, int i, const uint8_t* json_chunk, cgltf_mesh* out_mesh)
{
	CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_OBJECT);

	int size = tokens[i].size;
	++i;

	for (int j = 0; j < size; ++j)
	{
		CGLTF_CHECK_KEY(tokens[i]);

		if (cgltf_json_strcmp(tokens+i, json_chunk, "name") == 0)
		{
			i = cgltf_parse_json_string(options, tokens, i + 1, json_chunk, &out_mesh->name);
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "primitives") == 0)
		{
			i = cgltf_parse_json_array(options, tokens, i + 1, json_chunk, sizeof(cgltf_primitive), (void**)&out_mesh->primitives, &out_mesh->primitives_count);
			if (i < 0)
			{
				return i;
			}

			for (cgltf_size prim_index = 0; prim_index < out_mesh->primitives_count; ++prim_index)
			{
				i = cgltf_parse_json_primitive(options, tokens, i, json_chunk, &out_mesh->primitives[prim_index]);
				if (i < 0)
				{
					return i;
				}
			}
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "weights") == 0)
		{
			i = cgltf_parse_json_array(options, tokens, i + 1, json_chunk, sizeof(cgltf_float), (void**)&out_mesh->weights, &out_mesh->weights_count);
			if (i < 0)
			{
				return i;
			}

			i = cgltf_parse_json_float_array(tokens, i - 1, json_chunk, out_mesh->weights, (int)out_mesh->weights_count);
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "extras") == 0)
		{
			++i;

			out_mesh->extras.start_offset = tokens[i].start;
			out_mesh->extras.end_offset = tokens[i].end;

			if (tokens[i].type == JSMN_OBJECT)
			{
				int extras_size = tokens[i].size;
				++i;

				for (int k = 0; k < extras_size; ++k)
				{
					CGLTF_CHECK_KEY(tokens[i]);

					if (cgltf_json_strcmp(tokens+i, json_chunk, "targetNames") == 0 && tokens[i+1].type == JSMN_ARRAY)
					{
						i = cgltf_parse_json_string_array(options, tokens, i + 1, json_chunk, &out_mesh->target_names, &out_mesh->target_names_count);
					}
					else
					{
						i = cgltf_skip_json(tokens, i+1);
					}

					if (i < 0)
					{
						return i;
					}
				}
			}
			else
			{
				i = cgltf_skip_json(tokens, i);
			}
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "extensions") == 0)
		{
			i = cgltf_parse_json_unprocessed_extensions(options, tokens, i, json_chunk, &out_mesh->extensions_count, &out_mesh->extensions);
		}
		else
		{
			i = cgltf_skip_json(tokens, i+1);
		}

		if (i < 0)
		{
			return i;
		}
	}

	return i;
}

int cgltf_parse_json_meshes(cgltf_options* options, jsmntok_t const* tokens, int i, const uint8_t* json_chunk, cgltf_data* out_data)
{
	i = cgltf_parse_json_array(options, tokens, i, json_chunk, sizeof(cgltf_mesh), (void**)&out_data->meshes, &out_data->meshes_count);
	if (i < 0)
	{
		return i;
	}

	for (cgltf_size j = 0; j < out_data->meshes_count; ++j)
	{
		i = cgltf_parse_json_mesh(options, tokens, i, json_chunk, &out_data->meshes[j]);
		if (i < 0)
		{
			return i;
		}
	}
	return i;
}

cgltf_component_type cgltf_json_to_component_type(jsmntok_t const* tok, const uint8_t* json_chunk)
{
	int type = cgltf_json_to_int(tok, json_chunk);

	switch (type)
	{
	case 5120:
		return cgltf_component_type_r_8;
	case 5121:
		return cgltf_component_type_r_8u;
	case 5122:
		return cgltf_component_type_r_16;
	case 5123:
		return cgltf_component_type_r_16u;
	case 5125:
		return cgltf_component_type_r_32u;
	case 5126:
		return cgltf_component_type_r_32f;
	default:
		return cgltf_component_type_invalid;
	}
}

int cgltf_parse_json_accessor_sparse(cgltf_options* options, jsmntok_t const* tokens, int i, const uint8_t* json_chunk, cgltf_accessor_sparse* out_sparse)
{
	CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_OBJECT);

	int size = tokens[i].size;
	++i;

	for (int j = 0; j < size; ++j)
	{
		CGLTF_CHECK_KEY(tokens[i]);

		if (cgltf_json_strcmp(tokens+i, json_chunk, "count") == 0)
		{
			++i;
			out_sparse->count = cgltf_json_to_int(tokens + i, json_chunk);
			++i;
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "indices") == 0)
		{
			++i;
			CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_OBJECT);

			int indices_size = tokens[i].size;
			++i;

			for (int k = 0; k < indices_size; ++k)
			{
				CGLTF_CHECK_KEY(tokens[i]);

				if (cgltf_json_strcmp(tokens+i, json_chunk, "bufferView") == 0)
				{
					++i;
					out_sparse->indices_buffer_view = CGLTF_PTRINDEX(cgltf_buffer_view, cgltf_json_to_int(tokens + i, json_chunk));
					++i;
				}
				else if (cgltf_json_strcmp(tokens+i, json_chunk, "byteOffset") == 0)
				{
					++i;
					out_sparse->indices_byte_offset = cgltf_json_to_int(tokens + i, json_chunk);
					++i;
				}
				else if (cgltf_json_strcmp(tokens+i, json_chunk, "componentType") == 0)
				{
					++i;
					out_sparse->indices_component_type = cgltf_json_to_component_type(tokens + i, json_chunk);
					++i;
				}
				else if (cgltf_json_strcmp(tokens + i, json_chunk, "extras") == 0)
				{
					i = cgltf_parse_json_extras(tokens, i + 1, json_chunk, &out_sparse->indices_extras);
				}
				else if (cgltf_json_strcmp(tokens + i, json_chunk, "extensions") == 0)
				{
					i = cgltf_parse_json_unprocessed_extensions(options, tokens, i, json_chunk, &out_sparse->indices_extensions_count, &out_sparse->indices_extensions);
				}
				else
				{
					i = cgltf_skip_json(tokens, i+1);
				}

				if (i < 0)
				{
					return i;
				}
			}
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "values") == 0)
		{
			++i;
			CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_OBJECT);

			int values_size = tokens[i].size;
			++i;

			for (int k = 0; k < values_size; ++k)
			{
				CGLTF_CHECK_KEY(tokens[i]);

				if (cgltf_json_strcmp(tokens+i, json_chunk, "bufferView") == 0)
				{
					++i;
					out_sparse->values_buffer_view = CGLTF_PTRINDEX(cgltf_buffer_view, cgltf_json_to_int(tokens + i, json_chunk));
					++i;
				}
				else if (cgltf_json_strcmp(tokens+i, json_chunk, "byteOffset") == 0)
				{
					++i;
					out_sparse->values_byte_offset = cgltf_json_to_int(tokens + i, json_chunk);
					++i;
				}
				else if (cgltf_json_strcmp(tokens + i, json_chunk, "extras") == 0)
				{
					i = cgltf_parse_json_extras(tokens, i + 1, json_chunk, &out_sparse->values_extras);
				}
				else if (cgltf_json_strcmp(tokens + i, json_chunk, "extensions") == 0)
				{
					i = cgltf_parse_json_unprocessed_extensions(options, tokens, i, json_chunk, &out_sparse->values_extensions_count, &out_sparse->values_extensions);
				}
				else
				{
					i = cgltf_skip_json(tokens, i+1);
				}

				if (i < 0)
				{
					return i;
				}
			}
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "extras") == 0)
		{
			i = cgltf_parse_json_extras(tokens, i + 1, json_chunk, &out_sparse->extras);
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "extensions") == 0)
		{
			i = cgltf_parse_json_unprocessed_extensions(options, tokens, i, json_chunk, &out_sparse->extensions_count, &out_sparse->extensions);
		}
		else
		{
			i = cgltf_skip_json(tokens, i+1);
		}

		if (i < 0)
		{
			return i;
		}
	}

	return i;
}

int cgltf_parse_json_accessor(cgltf_options* options, jsmntok_t const* tokens, int i, const uint8_t* json_chunk, cgltf_accessor* out_accessor)
{
	CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_OBJECT);

	int size = tokens[i].size;
	++i;

	for (int j = 0; j < size; ++j)
	{
		CGLTF_CHECK_KEY(tokens[i]);

		if (cgltf_json_strcmp(tokens + i, json_chunk, "name") == 0)
		{
			i = cgltf_parse_json_string(options, tokens, i + 1, json_chunk, &out_accessor->name);
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "bufferView") == 0)
		{
			++i;
			out_accessor->buffer_view = CGLTF_PTRINDEX(cgltf_buffer_view, cgltf_json_to_int(tokens + i, json_chunk));
			++i;
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "byteOffset") == 0)
		{
			++i;
			out_accessor->offset =
					cgltf_json_to_int(tokens+i, json_chunk);
			++i;
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "componentType") == 0)
		{
			++i;
			out_accessor->component_type = cgltf_json_to_component_type(tokens + i, json_chunk);
			++i;
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "normalized") == 0)
		{
			++i;
			out_accessor->normalized = cgltf_json_to_bool(tokens+i, json_chunk);
			++i;
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "count") == 0)
		{
			++i;
			out_accessor->count =
					cgltf_json_to_int(tokens+i, json_chunk);
			++i;
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "type") == 0)
		{
			++i;
			if (cgltf_json_strcmp(tokens+i, json_chunk, "SCALAR") == 0)
			{
				out_accessor->type = cgltf_type_scalar;
			}
			else if (cgltf_json_strcmp(tokens+i, json_chunk, "VEC2") == 0)
			{
				out_accessor->type = cgltf_type_vec2;
			}
			else if (cgltf_json_strcmp(tokens+i, json_chunk, "VEC3") == 0)
			{
				out_accessor->type = cgltf_type_vec3;
			}
			else if (cgltf_json_strcmp(tokens+i, json_chunk, "VEC4") == 0)
			{
				out_accessor->type = cgltf_type_vec4;
			}
			else if (cgltf_json_strcmp(tokens+i, json_chunk, "MAT2") == 0)
			{
				out_accessor->type = cgltf_type_mat2;
			}
			else if (cgltf_json_strcmp(tokens+i, json_chunk, "MAT3") == 0)
			{
				out_accessor->type = cgltf_type_mat3;
			}
			else if (cgltf_json_strcmp(tokens+i, json_chunk, "MAT4") == 0)
			{
				out_accessor->type = cgltf_type_mat4;
			}
			++i;
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "min") == 0)
		{
			++i;
			out_accessor->has_min = 1;
			// note: we can't parse the precise number of elements since type may not have been computed yet
			int min_size = tokens[i].size > 16 ? 16 : tokens[i].size;
			i = cgltf_parse_json_float_array(tokens, i, json_chunk, out_accessor->min, min_size);
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "max") == 0)
		{
			++i;
			out_accessor->has_max = 1;
			// note: we can't parse the precise number of elements since type may not have been computed yet
			int max_size = tokens[i].size > 16 ? 16 : tokens[i].size;
			i = cgltf_parse_json_float_array(tokens, i, json_chunk, out_accessor->max, max_size);
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "sparse") == 0)
		{
			out_accessor->is_sparse = 1;
			i = cgltf_parse_json_accessor_sparse(options, tokens, i + 1, json_chunk, &out_accessor->sparse);
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "extras") == 0)
		{
			i = cgltf_parse_json_extras(tokens, i + 1, json_chunk, &out_accessor->extras);
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "extensions") == 0)
		{
			i = cgltf_parse_json_unprocessed_extensions(options, tokens, i, json_chunk, &out_accessor->extensions_count, &out_accessor->extensions);
		}
		else
		{
			i = cgltf_skip_json(tokens, i+1);
		}

		if (i < 0)
		{
			return i;
		}
	}

	return i;
}

int cgltf_parse_json_texture_transform(jsmntok_t const* tokens, int i, const uint8_t* json_chunk, cgltf_texture_transform* out_texture_transform)
{
	CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_OBJECT);

	int size = tokens[i].size;
	++i;

	for (int j = 0; j < size; ++j)
	{
		CGLTF_CHECK_KEY(tokens[i]);

		if (cgltf_json_strcmp(tokens + i, json_chunk, "offset") == 0)
		{
			i = cgltf_parse_json_float_array(tokens, i + 1, json_chunk, out_texture_transform->offset, 2);
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "rotation") == 0)
		{
			++i;
			out_texture_transform->rotation = cgltf_json_to_float(tokens + i, json_chunk);
			++i;
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "scale") == 0)
		{
			i = cgltf_parse_json_float_array(tokens, i + 1, json_chunk, out_texture_transform->scale, 2);
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "texCoord") == 0)
		{
			++i;
			out_texture_transform->texcoord = cgltf_json_to_int(tokens + i, json_chunk);
			++i;
		}
		else
		{
			i = cgltf_skip_json(tokens, i + 1);
		}

		if (i < 0)
		{
			return i;
		}
	}

	return i;
}

int cgltf_parse_json_texture_view(cgltf_options* options, jsmntok_t const* tokens, int i, const uint8_t* json_chunk, cgltf_texture_view* out_texture_view)
{
	CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_OBJECT);

	out_texture_view->scale = 1.0f;
	cgltf_fill_float_array(out_texture_view->transform.scale, 2, 1.0f);

	int size = tokens[i].size;
	++i;

	for (int j = 0; j < size; ++j)
	{
		CGLTF_CHECK_KEY(tokens[i]);

		if (cgltf_json_strcmp(tokens + i, json_chunk, "index") == 0)
		{
			++i;
			out_texture_view->texture = CGLTF_PTRINDEX(cgltf_texture, cgltf_json_to_int(tokens + i, json_chunk));
			++i;
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "texCoord") == 0)
		{
			++i;
			out_texture_view->texcoord = cgltf_json_to_int(tokens + i, json_chunk);
			++i;
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "scale") == 0) 
		{
			++i;
			out_texture_view->scale = cgltf_json_to_float(tokens + i, json_chunk);
			++i;
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "strength") == 0)
		{
			++i;
			out_texture_view->scale = cgltf_json_to_float(tokens + i, json_chunk);
			++i;
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "extras") == 0)
		{
			i = cgltf_parse_json_extras(tokens, i + 1, json_chunk, &out_texture_view->extras);
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "extensions") == 0)
		{
			++i;

			CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_OBJECT);
			if(out_texture_view->extensions)
			{
				return CGLTF_ERROR_JSON;
			}

			int extensions_size = tokens[i].size;
			out_texture_view->extensions_count = 0;
			out_texture_view->extensions = (cgltf_extension*)cgltf_calloc(options, sizeof(cgltf_extension), extensions_size);

			if (!out_texture_view->extensions)
			{
				return CGLTF_ERROR_NOMEM;
			}

			++i;

			for (int k = 0; k < extensions_size; ++k)
			{
				CGLTF_CHECK_KEY(tokens[i]);

				if (cgltf_json_strcmp(tokens+i, json_chunk, "KHR_texture_transform") == 0)
				{
					out_texture_view->has_transform = 1;
					i = cgltf_parse_json_texture_transform(tokens, i + 1, json_chunk, &out_texture_view->transform);
				}
				else
				{
					i = cgltf_parse_json_unprocessed_extension(options, tokens, i, json_chunk, &(out_texture_view->extensions[out_texture_view->extensions_count++]));
				}

				if (i < 0)
				{
					return i;
				}
			}
		}
		else
		{
			i = cgltf_skip_json(tokens, i + 1);
		}

		if (i < 0)
		{
			return i;
		}
	}

	return i;
}

int cgltf_parse_json_pbr_metallic_roughness(cgltf_options* options, jsmntok_t const* tokens, int i, const uint8_t* json_chunk, cgltf_pbr_metallic_roughness* out_pbr)
{
	CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_OBJECT);

	int size = tokens[i].size;
	++i;

	for (int j = 0; j < size; ++j)
	{
		CGLTF_CHECK_KEY(tokens[i]);

		if (cgltf_json_strcmp(tokens+i, json_chunk, "metallicFactor") == 0)
		{
			++i;
			out_pbr->metallic_factor = 
				cgltf_json_to_float(tokens + i, json_chunk);
			++i;
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "roughnessFactor") == 0) 
		{
			++i;
			out_pbr->roughness_factor =
				cgltf_json_to_float(tokens+i, json_chunk);
			++i;
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "baseColorFactor") == 0)
		{
			i = cgltf_parse_json_float_array(tokens, i + 1, json_chunk, out_pbr->base_color_factor, 4);
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "baseColorTexture") == 0)
		{
			i = cgltf_parse_json_texture_view(options, tokens, i + 1, json_chunk,
				&out_pbr->base_color_texture);
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "metallicRoughnessTexture") == 0)
		{
			i = cgltf_parse_json_texture_view(options, tokens, i + 1, json_chunk,
				&out_pbr->metallic_roughness_texture);
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "extras") == 0)
		{
			i = cgltf_parse_json_extras(tokens, i + 1, json_chunk, &out_pbr->extras);
		}
		else
		{
			i = cgltf_skip_json(tokens, i+1);
		}

		if (i < 0)
		{
			return i;
		}
	}

	return i;
}

int cgltf_parse_json_pbr_specular_glossiness(cgltf_options* options, jsmntok_t const* tokens, int i, const uint8_t* json_chunk, cgltf_pbr_specular_glossiness* out_pbr)
{
	CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_OBJECT);
	int size = tokens[i].size;
	++i;

	for (int j = 0; j < size; ++j)
	{
		CGLTF_CHECK_KEY(tokens[i]);

		if (cgltf_json_strcmp(tokens+i, json_chunk, "diffuseFactor") == 0)
		{
			i = cgltf_parse_json_float_array(tokens, i + 1, json_chunk, out_pbr->diffuse_factor, 4);
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "specularFactor") == 0)
		{
			i = cgltf_parse_json_float_array(tokens, i + 1, json_chunk, out_pbr->specular_factor, 3);
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "glossinessFactor") == 0)
		{
			++i;
			out_pbr->glossiness_factor = cgltf_json_to_float(tokens + i, json_chunk);
			++i;
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "diffuseTexture") == 0)
		{
			i = cgltf_parse_json_texture_view(options, tokens, i + 1, json_chunk, &out_pbr->diffuse_texture);
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "specularGlossinessTexture") == 0)
		{
			i = cgltf_parse_json_texture_view(options, tokens, i + 1, json_chunk, &out_pbr->specular_glossiness_texture);
		}
		else
		{
			i = cgltf_skip_json(tokens, i+1);
		}

		if (i < 0)
		{
			return i;
		}
	}

	return i;
}

int cgltf_parse_json_clearcoat(cgltf_options* options, jsmntok_t const* tokens, int i, const uint8_t* json_chunk, cgltf_clearcoat* out_clearcoat)
{
	CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_OBJECT);
	int size = tokens[i].size;
	++i;

	for (int j = 0; j < size; ++j)
	{
		CGLTF_CHECK_KEY(tokens[i]);

		if (cgltf_json_strcmp(tokens+i, json_chunk, "clearcoatFactor") == 0)
		{
			++i;
			out_clearcoat->clearcoat_factor = cgltf_json_to_float(tokens + i, json_chunk);
			++i;
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "clearcoatRoughnessFactor") == 0)
		{
			++i;
			out_clearcoat->clearcoat_roughness_factor = cgltf_json_to_float(tokens + i, json_chunk);
			++i;
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "clearcoatTexture") == 0)
		{
			i = cgltf_parse_json_texture_view(options, tokens, i + 1, json_chunk, &out_clearcoat->clearcoat_texture);
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "clearcoatRoughnessTexture") == 0)
		{
			i = cgltf_parse_json_texture_view(options, tokens, i + 1, json_chunk, &out_clearcoat->clearcoat_roughness_texture);
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "clearcoatNormalTexture") == 0)
		{
			i = cgltf_parse_json_texture_view(options, tokens, i + 1, json_chunk, &out_clearcoat->clearcoat_normal_texture);
		}
		else
		{
			i = cgltf_skip_json(tokens, i+1);
		}

		if (i < 0)
		{
			return i;
		}
	}

	return i;
}

int cgltf_parse_json_ior(jsmntok_t const* tokens, int i, const uint8_t* json_chunk, cgltf_ior* out_ior)
{
	CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_OBJECT);
	int size = tokens[i].size;
	++i;

	// Default values
	out_ior->ior = 1.5f;

	for (int j = 0; j < size; ++j)
	{
		CGLTF_CHECK_KEY(tokens[i]);

		if (cgltf_json_strcmp(tokens+i, json_chunk, "ior") == 0)
		{
			++i;
			out_ior->ior = cgltf_json_to_float(tokens + i, json_chunk);
			++i;
		}
		else
		{
			i = cgltf_skip_json(tokens, i+1);
		}

		if (i < 0)
		{
			return i;
		}
	}

	return i;
}

int cgltf_parse_json_specular(cgltf_options* options, jsmntok_t const* tokens, int i, const uint8_t* json_chunk, cgltf_specular* out_specular)
{
	CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_OBJECT);
	int size = tokens[i].size;
	++i;

	// Default values
	out_specular->specular_factor = 1.0f;
	cgltf_fill_float_array(out_specular->specular_color_factor, 3, 1.0f);

	for (int j = 0; j < size; ++j)
	{
		CGLTF_CHECK_KEY(tokens[i]);

		if (cgltf_json_strcmp(tokens+i, json_chunk, "specularFactor") == 0)
		{
			++i;
			out_specular->specular_factor = cgltf_json_to_float(tokens + i, json_chunk);
			++i;
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "specularColorFactor") == 0)
		{
			i = cgltf_parse_json_float_array(tokens, i + 1, json_chunk, out_specular->specular_color_factor, 3);
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "specularTexture") == 0)
		{
			i = cgltf_parse_json_texture_view(options, tokens, i + 1, json_chunk, &out_specular->specular_texture);
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "specularColorTexture") == 0)
		{
			i = cgltf_parse_json_texture_view(options, tokens, i + 1, json_chunk, &out_specular->specular_color_texture);
		}
		else
		{
			i = cgltf_skip_json(tokens, i+1);
		}

		if (i < 0)
		{
			return i;
		}
	}

	return i;
}

int cgltf_parse_json_transmission(cgltf_options* options, jsmntok_t const* tokens, int i, const uint8_t* json_chunk, cgltf_transmission* out_transmission)
{
	CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_OBJECT);
	int size = tokens[i].size;
	++i;

	for (int j = 0; j < size; ++j)
	{
		CGLTF_CHECK_KEY(tokens[i]);

		if (cgltf_json_strcmp(tokens+i, json_chunk, "transmissionFactor") == 0)
		{
			++i;
			out_transmission->transmission_factor = cgltf_json_to_float(tokens + i, json_chunk);
			++i;
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "transmissionTexture") == 0)
		{
			i = cgltf_parse_json_texture_view(options, tokens, i + 1, json_chunk, &out_transmission->transmission_texture);
		}
		else
		{
			i = cgltf_skip_json(tokens, i+1);
		}

		if (i < 0)
		{
			return i;
		}
	}

	return i;
}

int cgltf_parse_json_volume(cgltf_options* options, jsmntok_t const* tokens, int i, const uint8_t* json_chunk, cgltf_volume* out_volume)
{
	CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_OBJECT);
	int size = tokens[i].size;
	++i;

	for (int j = 0; j < size; ++j)
	{
		CGLTF_CHECK_KEY(tokens[i]);

		if (cgltf_json_strcmp(tokens + i, json_chunk, "thicknessFactor") == 0)
		{
			++i;
			out_volume->thickness_factor = cgltf_json_to_float(tokens + i, json_chunk);
			++i;
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "thicknessTexture") == 0)
		{
			i = cgltf_parse_json_texture_view(options, tokens, i + 1, json_chunk, &out_volume->thickness_texture);
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "attenuationColor") == 0)
		{
			i = cgltf_parse_json_float_array(tokens, i + 1, json_chunk, out_volume->attenuation_color, 3);
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "attenuationDistance") == 0)
		{
			++i;
			out_volume->attenuation_distance = cgltf_json_to_float(tokens + i, json_chunk);
			++i;
		}
		else
		{
			i = cgltf_skip_json(tokens, i + 1);
		}

		if (i < 0)
		{
			return i;
		}
	}

	return i;
}

int cgltf_parse_json_sheen(cgltf_options* options, jsmntok_t const* tokens, int i, const uint8_t* json_chunk, cgltf_sheen* out_sheen)
{
	CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_OBJECT);
	int size = tokens[i].size;
	++i;

	for (int j = 0; j < size; ++j)
	{
		CGLTF_CHECK_KEY(tokens[i]);

		if (cgltf_json_strcmp(tokens+i, json_chunk, "sheenColorFactor") == 0)
		{
			i = cgltf_parse_json_float_array(tokens, i + 1, json_chunk, out_sheen->sheen_color_factor, 3);
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "sheenColorTexture") == 0)
		{
			i = cgltf_parse_json_texture_view(options, tokens, i + 1, json_chunk, &out_sheen->sheen_color_texture);
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "sheenRoughnessFactor") == 0)
		{
			++i;
			out_sheen->sheen_roughness_factor = cgltf_json_to_float(tokens + i, json_chunk);
			++i;
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "sheenRoughnessTexture") == 0)
		{
			i = cgltf_parse_json_texture_view(options, tokens, i + 1, json_chunk, &out_sheen->sheen_roughness_texture);
		}
		else
		{
			i = cgltf_skip_json(tokens, i+1);
		}

		if (i < 0)
		{
			return i;
		}
	}

	return i;
}

int cgltf_parse_json_image(cgltf_options* options, jsmntok_t const* tokens, int i, const uint8_t* json_chunk, cgltf_image* out_image)
{
	CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_OBJECT);

	int size = tokens[i].size;
	++i;

	for (int j = 0; j < size; ++j) 
	{
		CGLTF_CHECK_KEY(tokens[i]);

		if (cgltf_json_strcmp(tokens + i, json_chunk, "uri") == 0) 
		{
			i = cgltf_parse_json_string(options, tokens, i + 1, json_chunk, &out_image->uri);
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "bufferView") == 0)
		{
			++i;
			out_image->buffer_view = CGLTF_PTRINDEX(cgltf_buffer_view, cgltf_json_to_int(tokens + i, json_chunk));
			++i;
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "mimeType") == 0)
		{
			i = cgltf_parse_json_string(options, tokens, i + 1, json_chunk, &out_image->mime_type);
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "name") == 0)
		{
			i = cgltf_parse_json_string(options, tokens, i + 1, json_chunk, &out_image->name);
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "extras") == 0)
		{
			i = cgltf_parse_json_extras(tokens, i + 1, json_chunk, &out_image->extras);
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "extensions") == 0)
		{
			i = cgltf_parse_json_unprocessed_extensions(options, tokens, i, json_chunk, &out_image->extensions_count, &out_image->extensions);
		}
		else
		{
			i = cgltf_skip_json(tokens, i + 1);
		}

		if (i < 0)
		{
			return i;
		}
	}

	return i;
}

int cgltf_parse_json_sampler(cgltf_options* options, jsmntok_t const* tokens, int i, const uint8_t* json_chunk, cgltf_sampler* out_sampler)
{
	(void)options;
	CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_OBJECT);

	out_sampler->wrap_s = 10497;
	out_sampler->wrap_t = 10497;

	int size = tokens[i].size;
	++i;

	for (int j = 0; j < size; ++j)
	{
		CGLTF_CHECK_KEY(tokens[i]);

		if (cgltf_json_strcmp(tokens + i, json_chunk, "name") == 0)
		{
			i = cgltf_parse_json_string(options, tokens, i + 1, json_chunk, &out_sampler->name);
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "magFilter") == 0)
		{
			++i;
			out_sampler->mag_filter
				= cgltf_json_to_int(tokens + i, json_chunk);
			++i;
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "minFilter") == 0)
		{
			++i;
			out_sampler->min_filter
				= cgltf_json_to_int(tokens + i, json_chunk);
			++i;
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "wrapS") == 0)
		{
			++i;
			out_sampler->wrap_s
				= cgltf_json_to_int(tokens + i, json_chunk);
			++i;
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "wrapT") == 0) 
		{
			++i;
			out_sampler->wrap_t
				= cgltf_json_to_int(tokens + i, json_chunk);
			++i;
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "extras") == 0)
		{
			i = cgltf_parse_json_extras(tokens, i + 1, json_chunk, &out_sampler->extras);
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "extensions") == 0)
		{
			i = cgltf_parse_json_unprocessed_extensions(options, tokens, i, json_chunk, &out_sampler->extensions_count, &out_sampler->extensions);
		}
		else
		{
			i = cgltf_skip_json(tokens, i + 1);
		}

		if (i < 0)
		{
			return i;
		}
	}

	return i;
}

int cgltf_parse_json_texture(cgltf_options* options, jsmntok_t const* tokens, int i, const uint8_t* json_chunk, cgltf_texture* out_texture)
{
	CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_OBJECT);

	int size = tokens[i].size;
	++i;

	for (int j = 0; j < size; ++j)
	{
		CGLTF_CHECK_KEY(tokens[i]);

		if (cgltf_json_strcmp(tokens+i, json_chunk, "name") == 0)
		{
			i = cgltf_parse_json_string(options, tokens, i + 1, json_chunk, &out_texture->name);
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "sampler") == 0)
		{
			++i;
			out_texture->sampler = CGLTF_PTRINDEX(cgltf_sampler, cgltf_json_to_int(tokens + i, json_chunk));
			++i;
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "source") == 0) 
		{
			++i;
			out_texture->image = CGLTF_PTRINDEX(cgltf_image, cgltf_json_to_int(tokens + i, json_chunk));
			++i;
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "extras") == 0)
		{
			i = cgltf_parse_json_extras(tokens, i + 1, json_chunk, &out_texture->extras);
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "extensions") == 0)
		{
			++i;

			CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_OBJECT);
			if (out_texture->extensions)
			{
				return CGLTF_ERROR_JSON;
			}

			int extensions_size = tokens[i].size;
			++i;
			out_texture->extensions = (cgltf_extension*)cgltf_calloc(options, sizeof(cgltf_extension), extensions_size);
			out_texture->extensions_count = 0;

			if (!out_texture->extensions)
			{
				return CGLTF_ERROR_NOMEM;
			}

			for (int k = 0; k < extensions_size; ++k)
			{
				CGLTF_CHECK_KEY(tokens[i]);

				if (cgltf_json_strcmp(tokens + i, json_chunk, "KHR_texture_basisu") == 0)
				{
					out_texture->has_basisu = 1;
					++i;
					CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_OBJECT);
					int num_properties = tokens[i].size;
					++i;

					for (int t = 0; t < num_properties; ++t)
					{
						CGLTF_CHECK_KEY(tokens[i]);

						if (cgltf_json_strcmp(tokens + i, json_chunk, "source") == 0)
						{
							++i;
							out_texture->basisu_image = CGLTF_PTRINDEX(cgltf_image, cgltf_json_to_int(tokens + i, json_chunk));
							++i;
						}
						else
						{
							i = cgltf_skip_json(tokens, i + 1);
						}
					}
				}
				else
				{
					i = cgltf_parse_json_unprocessed_extension(options, tokens, i, json_chunk, &(out_texture->extensions[out_texture->extensions_count++]));
				}

				if (i < 0)
				{
					return i;
				}
			}
		}
		else
		{
			i = cgltf_skip_json(tokens, i + 1);
		}

		if (i < 0)
		{
			return i;
		}
	}

	return i;
}

int cgltf_parse_json_material(cgltf_options* options, jsmntok_t const* tokens, int i, const uint8_t* json_chunk, cgltf_material* out_material)
{
	CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_OBJECT);

	cgltf_fill_float_array(out_material->pbr_metallic_roughness.base_color_factor, 4, 1.0f);
	out_material->pbr_metallic_roughness.metallic_factor = 1.0f;
	out_material->pbr_metallic_roughness.roughness_factor = 1.0f;

	cgltf_fill_float_array(out_material->pbr_specular_glossiness.diffuse_factor, 4, 1.0f);
	cgltf_fill_float_array(out_material->pbr_specular_glossiness.specular_factor, 3, 1.0f);
	out_material->pbr_specular_glossiness.glossiness_factor = 1.0f;

	cgltf_fill_float_array(out_material->volume.attenuation_color, 3, 1.0f);
	out_material->volume.attenuation_distance = FLT_MAX;

	out_material->alpha_cutoff = 0.5f;

	int size = tokens[i].size;
	++i;

	for (int j = 0; j < size; ++j)
	{
		CGLTF_CHECK_KEY(tokens[i]);

		if (cgltf_json_strcmp(tokens+i, json_chunk, "name") == 0)
		{
			i = cgltf_parse_json_string(options, tokens, i + 1, json_chunk, &out_material->name);
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "pbrMetallicRoughness") == 0)
		{
			out_material->has_pbr_metallic_roughness = 1;
			i = cgltf_parse_json_pbr_metallic_roughness(options, tokens, i + 1, json_chunk, &out_material->pbr_metallic_roughness);
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "emissiveFactor") == 0)
		{
			i = cgltf_parse_json_float_array(tokens, i + 1, json_chunk, out_material->emissive_factor, 3);
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "normalTexture") == 0)
		{
			i = cgltf_parse_json_texture_view(options, tokens, i + 1, json_chunk,
				&out_material->normal_texture);
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "occlusionTexture") == 0)
		{
			i = cgltf_parse_json_texture_view(options, tokens, i + 1, json_chunk,
				&out_material->occlusion_texture);
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "emissiveTexture") == 0)
		{
			i = cgltf_parse_json_texture_view(options, tokens, i + 1, json_chunk,
				&out_material->emissive_texture);
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "alphaMode") == 0)
		{
			++i;
			if (cgltf_json_strcmp(tokens + i, json_chunk, "OPAQUE") == 0)
			{
				out_material->alpha_mode = cgltf_alpha_mode_opaque;
			}
			else if (cgltf_json_strcmp(tokens + i, json_chunk, "MASK") == 0)
			{
				out_material->alpha_mode = cgltf_alpha_mode_mask;
			}
			else if (cgltf_json_strcmp(tokens + i, json_chunk, "BLEND") == 0)
			{
				out_material->alpha_mode = cgltf_alpha_mode_blend;
			}
			++i;
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "alphaCutoff") == 0)
		{
			++i;
			out_material->alpha_cutoff = cgltf_json_to_float(tokens + i, json_chunk);
			++i;
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "doubleSided") == 0)
		{
			++i;
			out_material->double_sided =
				cgltf_json_to_bool(tokens + i, json_chunk);
			++i;
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "extras") == 0)
		{
			i = cgltf_parse_json_extras(tokens, i + 1, json_chunk, &out_material->extras);
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "extensions") == 0)
		{
			++i;

			CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_OBJECT);
			if(out_material->extensions)
			{
				return CGLTF_ERROR_JSON;
			}

			int extensions_size = tokens[i].size;
			++i;
			out_material->extensions = (cgltf_extension*)cgltf_calloc(options, sizeof(cgltf_extension), extensions_size);
			out_material->extensions_count= 0;

			if (!out_material->extensions)
			{
				return CGLTF_ERROR_NOMEM;
			}

			for (int k = 0; k < extensions_size; ++k)
			{
				CGLTF_CHECK_KEY(tokens[i]);

				if (cgltf_json_strcmp(tokens+i, json_chunk, "KHR_materials_pbrSpecularGlossiness") == 0)
				{
					out_material->has_pbr_specular_glossiness = 1;
					i = cgltf_parse_json_pbr_specular_glossiness(options, tokens, i + 1, json_chunk, &out_material->pbr_specular_glossiness);
				}
				else if (cgltf_json_strcmp(tokens+i, json_chunk, "KHR_materials_unlit") == 0)
				{
					out_material->unlit = 1;
					i = cgltf_skip_json(tokens, i+1);
				}
				else if (cgltf_json_strcmp(tokens+i, json_chunk, "KHR_materials_clearcoat") == 0)
				{
					out_material->has_clearcoat = 1;
					i = cgltf_parse_json_clearcoat(options, tokens, i + 1, json_chunk, &out_material->clearcoat);
				}
				else if (cgltf_json_strcmp(tokens+i, json_chunk, "KHR_materials_ior") == 0)
				{
					out_material->has_ior = 1;
					i = cgltf_parse_json_ior(tokens, i + 1, json_chunk, &out_material->ior);
				}
				else if (cgltf_json_strcmp(tokens+i, json_chunk, "KHR_materials_specular") == 0)
				{
					out_material->has_specular = 1;
					i = cgltf_parse_json_specular(options, tokens, i + 1, json_chunk, &out_material->specular);
				}
				else if (cgltf_json_strcmp(tokens+i, json_chunk, "KHR_materials_transmission") == 0)
				{
					out_material->has_transmission = 1;
					i = cgltf_parse_json_transmission(options, tokens, i + 1, json_chunk, &out_material->transmission);
				}
				else if (cgltf_json_strcmp(tokens + i, json_chunk, "KHR_materials_volume") == 0)
				{
					out_material->has_volume = 1;
					i = cgltf_parse_json_volume(options, tokens, i + 1, json_chunk, &out_material->volume);
				}
				else if (cgltf_json_strcmp(tokens+i, json_chunk, "KHR_materials_sheen") == 0)
				{
					out_material->has_sheen = 1;
					i = cgltf_parse_json_sheen(options, tokens, i + 1, json_chunk, &out_material->sheen);
				}
				else
				{
					i = cgltf_parse_json_unprocessed_extension(options, tokens, i, json_chunk, &(out_material->extensions[out_material->extensions_count++]));
				}

				if (i < 0)
				{
					return i;
				}
			}
		}
		else
		{
			i = cgltf_skip_json(tokens, i+1);
		}

		if (i < 0)
		{
			return i;
		}
	}

	return i;
}

int cgltf_parse_json_accessors(cgltf_options* options, jsmntok_t const* tokens, int i, const uint8_t* json_chunk, cgltf_data* out_data)
{
	i = cgltf_parse_json_array(options, tokens, i, json_chunk, sizeof(cgltf_accessor), (void**)&out_data->accessors, &out_data->accessors_count);
	if (i < 0)
	{
		return i;
	}

	for (cgltf_size j = 0; j < out_data->accessors_count; ++j)
	{
		i = cgltf_parse_json_accessor(options, tokens, i, json_chunk, &out_data->accessors[j]);
		if (i < 0)
		{
			return i;
		}
	}
	return i;
}

int cgltf_parse_json_materials(cgltf_options* options, jsmntok_t const* tokens, int i, const uint8_t* json_chunk, cgltf_data* out_data)
{
	i = cgltf_parse_json_array(options, tokens, i, json_chunk, sizeof(cgltf_material), (void**)&out_data->materials, &out_data->materials_count);
	if (i < 0)
	{
		return i;
	}

	for (cgltf_size j = 0; j < out_data->materials_count; ++j)
	{
		i = cgltf_parse_json_material(options, tokens, i, json_chunk, &out_data->materials[j]);
		if (i < 0)
		{
			return i;
		}
	}
	return i;
}

int cgltf_parse_json_images(cgltf_options* options, jsmntok_t const* tokens, int i, const uint8_t* json_chunk, cgltf_data* out_data)
{
	i = cgltf_parse_json_array(options, tokens, i, json_chunk, sizeof(cgltf_image), (void**)&out_data->images, &out_data->images_count);
	if (i < 0)
	{
		return i;
	}

	for (cgltf_size j = 0; j < out_data->images_count; ++j)
	{
		i = cgltf_parse_json_image(options, tokens, i, json_chunk, &out_data->images[j]);
		if (i < 0)
		{
			return i;
		}
	}
	return i;
}

int cgltf_parse_json_textures(cgltf_options* options, jsmntok_t const* tokens, int i, const uint8_t* json_chunk, cgltf_data* out_data)
{
	i = cgltf_parse_json_array(options, tokens, i, json_chunk, sizeof(cgltf_texture), (void**)&out_data->textures, &out_data->textures_count);
	if (i < 0)
	{
		return i;
	}

	for (cgltf_size j = 0; j < out_data->textures_count; ++j)
	{
		i = cgltf_parse_json_texture(options, tokens, i, json_chunk, &out_data->textures[j]);
		if (i < 0)
		{
			return i;
		}
	}
	return i;
}

int cgltf_parse_json_samplers(cgltf_options* options, jsmntok_t const* tokens, int i, const uint8_t* json_chunk, cgltf_data* out_data)
{
	i = cgltf_parse_json_array(options, tokens, i, json_chunk, sizeof(cgltf_sampler), (void**)&out_data->samplers, &out_data->samplers_count);
	if (i < 0)
	{
		return i;
	}

	for (cgltf_size j = 0; j < out_data->samplers_count; ++j)
	{
		i = cgltf_parse_json_sampler(options, tokens, i, json_chunk, &out_data->samplers[j]);
		if (i < 0)
		{
			return i;
		}
	}
	return i;
}

int cgltf_parse_json_meshopt_compression(cgltf_options* options, jsmntok_t const* tokens, int i, const uint8_t* json_chunk, cgltf_meshopt_compression* out_meshopt_compression)
{
	(void)options;
	CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_OBJECT);

	int size = tokens[i].size;
	++i;

	for (int j = 0; j < size; ++j)
	{
		CGLTF_CHECK_KEY(tokens[i]);

		if (cgltf_json_strcmp(tokens+i, json_chunk, "buffer") == 0)
		{
			++i;
			out_meshopt_compression->buffer = CGLTF_PTRINDEX(cgltf_buffer, cgltf_json_to_int(tokens + i, json_chunk));
			++i;
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "byteOffset") == 0)
		{
			++i;
			out_meshopt_compression->offset = cgltf_json_to_int(tokens+i, json_chunk);
			++i;
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "byteLength") == 0)
		{
			++i;
			out_meshopt_compression->size = cgltf_json_to_int(tokens+i, json_chunk);
			++i;
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "byteStride") == 0)
		{
			++i;
			out_meshopt_compression->stride = cgltf_json_to_int(tokens+i, json_chunk);
			++i;
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "count") == 0)
		{
			++i;
			out_meshopt_compression->count = cgltf_json_to_int(tokens+i, json_chunk);
			++i;
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "mode") == 0)
		{
			++i;
			if (cgltf_json_strcmp(tokens+i, json_chunk, "ATTRIBUTES") == 0)
			{
				out_meshopt_compression->mode = cgltf_meshopt_compression_mode_attributes;
			}
			else if (cgltf_json_strcmp(tokens+i, json_chunk, "TRIANGLES") == 0)
			{
				out_meshopt_compression->mode = cgltf_meshopt_compression_mode_triangles;
			}
			else if (cgltf_json_strcmp(tokens+i, json_chunk, "INDICES") == 0)
			{
				out_meshopt_compression->mode = cgltf_meshopt_compression_mode_indices;
			}
			++i;
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "filter") == 0)
		{
			++i;
			if (cgltf_json_strcmp(tokens+i, json_chunk, "NONE") == 0)
			{
				out_meshopt_compression->filter = cgltf_meshopt_compression_filter_none;
			}
			else if (cgltf_json_strcmp(tokens+i, json_chunk, "OCTAHEDRAL") == 0)
			{
				out_meshopt_compression->filter = cgltf_meshopt_compression_filter_octahedral;
			}
			else if (cgltf_json_strcmp(tokens+i, json_chunk, "QUATERNION") == 0)
			{
				out_meshopt_compression->filter = cgltf_meshopt_compression_filter_quaternion;
			}
			else if (cgltf_json_strcmp(tokens+i, json_chunk, "EXPONENTIAL") == 0)
			{
				out_meshopt_compression->filter = cgltf_meshopt_compression_filter_exponential;
			}
			++i;
		}
		else
		{
			i = cgltf_skip_json(tokens, i+1);
		}

		if (i < 0)
		{
			return i;
		}
	}

	return i;
}

int cgltf_parse_json_buffer_view(cgltf_options* options, jsmntok_t const* tokens, int i, const uint8_t* json_chunk, cgltf_buffer_view* out_buffer_view)
{
	CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_OBJECT);

	int size = tokens[i].size;
	++i;

	for (int j = 0; j < size; ++j)
	{
		CGLTF_CHECK_KEY(tokens[i]);

		if (cgltf_json_strcmp(tokens + i, json_chunk, "name") == 0)
		{
			i = cgltf_parse_json_string(options, tokens, i + 1, json_chunk, &out_buffer_view->name);
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "buffer") == 0)
		{
			++i;
			out_buffer_view->buffer = CGLTF_PTRINDEX(cgltf_buffer, cgltf_json_to_int(tokens + i, json_chunk));
			++i;
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "byteOffset") == 0)
		{
			++i;
			out_buffer_view->offset =
					cgltf_json_to_int(tokens+i, json_chunk);
			++i;
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "byteLength") == 0)
		{
			++i;
			out_buffer_view->size =
					cgltf_json_to_int(tokens+i, json_chunk);
			++i;
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "byteStride") == 0)
		{
			++i;
			out_buffer_view->stride =
					cgltf_json_to_int(tokens+i, json_chunk);
			++i;
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "target") == 0)
		{
			++i;
			int type = cgltf_json_to_int(tokens+i, json_chunk);
			switch (type)
			{
			case 34962:
				type = cgltf_buffer_view_type_vertices;
				break;
			case 34963:
				type = cgltf_buffer_view_type_indices;
				break;
			default:
				type = cgltf_buffer_view_type_invalid;
				break;
			}
			out_buffer_view->type = (cgltf_buffer_view_type)type;
			++i;
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "extras") == 0)
		{
			i = cgltf_parse_json_extras(tokens, i + 1, json_chunk, &out_buffer_view->extras);
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "extensions") == 0)
		{
			++i;

			CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_OBJECT);
			if(out_buffer_view->extensions)
			{
				return CGLTF_ERROR_JSON;
			}

			int extensions_size = tokens[i].size;
			out_buffer_view->extensions_count = 0;
			out_buffer_view->extensions = (cgltf_extension*)cgltf_calloc(options, sizeof(cgltf_extension), extensions_size);

			if (!out_buffer_view->extensions)
			{
				return CGLTF_ERROR_NOMEM;
			}

			++i;
			for (int k = 0; k < extensions_size; ++k)
			{
				CGLTF_CHECK_KEY(tokens[i]);

				if (cgltf_json_strcmp(tokens+i, json_chunk, "EXT_meshopt_compression") == 0)
				{
					out_buffer_view->has_meshopt_compression = 1;
					i = cgltf_parse_json_meshopt_compression(options, tokens, i + 1, json_chunk, &out_buffer_view->meshopt_compression);
				}
				else
				{
					i = cgltf_parse_json_unprocessed_extension(options, tokens, i, json_chunk, &(out_buffer_view->extensions[out_buffer_view->extensions_count++]));
				}

				if (i < 0)
				{
					return i;
				}
			}
		}
		else
		{
			i = cgltf_skip_json(tokens, i+1);
		}

		if (i < 0)
		{
			return i;
		}
	}

	return i;
}

int cgltf_parse_json_buffer_views(cgltf_options* options, jsmntok_t const* tokens, int i, const uint8_t* json_chunk, cgltf_data* out_data)
{
	i = cgltf_parse_json_array(options, tokens, i, json_chunk, sizeof(cgltf_buffer_view), (void**)&out_data->buffer_views, &out_data->buffer_views_count);
	if (i < 0)
	{
		return i;
	}

	for (cgltf_size j = 0; j < out_data->buffer_views_count; ++j)
	{
		i = cgltf_parse_json_buffer_view(options, tokens, i, json_chunk, &out_data->buffer_views[j]);
		if (i < 0)
		{
			return i;
		}
	}
	return i;
}

int cgltf_parse_json_buffer(cgltf_options* options, jsmntok_t const* tokens, int i, const uint8_t* json_chunk, cgltf_buffer* out_buffer)
{
	CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_OBJECT);

	int size = tokens[i].size;
	++i;

	for (int j = 0; j < size; ++j)
	{
		CGLTF_CHECK_KEY(tokens[i]);

		if (cgltf_json_strcmp(tokens + i, json_chunk, "name") == 0)
		{
			i = cgltf_parse_json_string(options, tokens, i + 1, json_chunk, &out_buffer->name);
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "byteLength") == 0)
		{
			++i;
			out_buffer->size =
					cgltf_json_to_int(tokens+i, json_chunk);
			++i;
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "uri") == 0)
		{
			i = cgltf_parse_json_string(options, tokens, i + 1, json_chunk, &out_buffer->uri);
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "extras") == 0)
		{
			i = cgltf_parse_json_extras(tokens, i + 1, json_chunk, &out_buffer->extras);
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "extensions") == 0)
		{
			i = cgltf_parse_json_unprocessed_extensions(options, tokens, i, json_chunk, &out_buffer->extensions_count, &out_buffer->extensions);
		}
		else
		{
			i = cgltf_skip_json(tokens, i+1);
		}

		if (i < 0)
		{
			return i;
		}
	}

	return i;
}

int cgltf_parse_json_buffers(cgltf_options* options, jsmntok_t const* tokens, int i, const uint8_t* json_chunk, cgltf_data* out_data)
{
	i = cgltf_parse_json_array(options, tokens, i, json_chunk, sizeof(cgltf_buffer), (void**)&out_data->buffers, &out_data->buffers_count);
	if (i < 0)
	{
		return i;
	}

	for (cgltf_size j = 0; j < out_data->buffers_count; ++j)
	{
		i = cgltf_parse_json_buffer(options, tokens, i, json_chunk, &out_data->buffers[j]);
		if (i < 0)
		{
			return i;
		}
	}
	return i;
}

int cgltf_parse_json_skin(cgltf_options* options, jsmntok_t const* tokens, int i, const uint8_t* json_chunk, cgltf_skin* out_skin)
{
	CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_OBJECT);

	int size = tokens[i].size;
	++i;

	for (int j = 0; j < size; ++j)
	{
		CGLTF_CHECK_KEY(tokens[i]);

		if (cgltf_json_strcmp(tokens+i, json_chunk, "name") == 0)
		{
			i = cgltf_parse_json_string(options, tokens, i + 1, json_chunk, &out_skin->name);
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "joints") == 0)
		{
			i = cgltf_parse_json_array(options, tokens, i + 1, json_chunk, sizeof(cgltf_node*), (void**)&out_skin->joints, &out_skin->joints_count);
			if (i < 0)
			{
				return i;
			}

			for (cgltf_size k = 0; k < out_skin->joints_count; ++k)
			{
				out_skin->joints[k] = CGLTF_PTRINDEX(cgltf_node, cgltf_json_to_int(tokens + i, json_chunk));
				++i;
			}
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "skeleton") == 0)
		{
			++i;
			CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_PRIMITIVE);
			out_skin->skeleton = CGLTF_PTRINDEX(cgltf_node, cgltf_json_to_int(tokens + i, json_chunk));
			++i;
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "inverseBindMatrices") == 0)
		{
			++i;
			CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_PRIMITIVE);
			out_skin->inverse_bind_matrices = CGLTF_PTRINDEX(cgltf_accessor, cgltf_json_to_int(tokens + i, json_chunk));
			++i;
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "extras") == 0)
		{
			i = cgltf_parse_json_extras(tokens, i + 1, json_chunk, &out_skin->extras);
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "extensions") == 0)
		{
			i = cgltf_parse_json_unprocessed_extensions(options, tokens, i, json_chunk, &out_skin->extensions_count, &out_skin->extensions);
		}
		else
		{
			i = cgltf_skip_json(tokens, i+1);
		}

		if (i < 0)
		{
			return i;
		}
	}

	return i;
}

int cgltf_parse_json_skins(cgltf_options* options, jsmntok_t const* tokens, int i, const uint8_t* json_chunk, cgltf_data* out_data)
{
	i = cgltf_parse_json_array(options, tokens, i, json_chunk, sizeof(cgltf_skin), (void**)&out_data->skins, &out_data->skins_count);
	if (i < 0)
	{
		return i;
	}

	for (cgltf_size j = 0; j < out_data->skins_count; ++j)
	{
		i = cgltf_parse_json_skin(options, tokens, i, json_chunk, &out_data->skins[j]);
		if (i < 0)
		{
			return i;
		}
	}
	return i;
}

int cgltf_parse_json_camera(cgltf_options* options, jsmntok_t const* tokens, int i, const uint8_t* json_chunk, cgltf_camera* out_camera)
{
	CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_OBJECT);

	int size = tokens[i].size;
	++i;

	for (int j = 0; j < size; ++j)
	{
		CGLTF_CHECK_KEY(tokens[i]);

		if (cgltf_json_strcmp(tokens+i, json_chunk, "name") == 0)
		{
			i = cgltf_parse_json_string(options, tokens, i + 1, json_chunk, &out_camera->name);
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "type") == 0)
		{
			++i;
			if (cgltf_json_strcmp(tokens + i, json_chunk, "perspective") == 0)
			{
				out_camera->type = cgltf_camera_type_perspective;
			}
			else if (cgltf_json_strcmp(tokens + i, json_chunk, "orthographic") == 0)
			{
				out_camera->type = cgltf_camera_type_orthographic;
			}
			++i;
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "perspective") == 0)
		{
			++i;

			CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_OBJECT);

			int data_size = tokens[i].size;
			++i;

			out_camera->type = cgltf_camera_type_perspective;

			for (int k = 0; k < data_size; ++k)
			{
				CGLTF_CHECK_KEY(tokens[i]);

				if (cgltf_json_strcmp(tokens+i, json_chunk, "aspectRatio") == 0)
				{
					++i;
					out_camera->data.perspective.has_aspect_ratio = 1;
					out_camera->data.perspective.aspect_ratio = cgltf_json_to_float(tokens + i, json_chunk);
					++i;
				}
				else if (cgltf_json_strcmp(tokens+i, json_chunk, "yfov") == 0)
				{
					++i;
					out_camera->data.perspective.yfov = cgltf_json_to_float(tokens + i, json_chunk);
					++i;
				}
				else if (cgltf_json_strcmp(tokens+i, json_chunk, "zfar") == 0)
				{
					++i;
					out_camera->data.perspective.has_zfar = 1;
					out_camera->data.perspective.zfar = cgltf_json_to_float(tokens + i, json_chunk);
					++i;
				}
				else if (cgltf_json_strcmp(tokens+i, json_chunk, "znear") == 0)
				{
					++i;
					out_camera->data.perspective.znear = cgltf_json_to_float(tokens + i, json_chunk);
					++i;
				}
				else if (cgltf_json_strcmp(tokens + i, json_chunk, "extras") == 0)
				{
					i = cgltf_parse_json_extras(tokens, i + 1, json_chunk, &out_camera->data.perspective.extras);
				}
				else
				{
					i = cgltf_skip_json(tokens, i+1);
				}

				if (i < 0)
				{
					return i;
				}
			}
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "orthographic") == 0)
		{
			++i;

			CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_OBJECT);

			int data_size = tokens[i].size;
			++i;

			out_camera->type = cgltf_camera_type_orthographic;

			for (int k = 0; k < data_size; ++k)
			{
				CGLTF_CHECK_KEY(tokens[i]);

				if (cgltf_json_strcmp(tokens+i, json_chunk, "xmag") == 0)
				{
					++i;
					out_camera->data.orthographic.xmag = cgltf_json_to_float(tokens + i, json_chunk);
					++i;
				}
				else if (cgltf_json_strcmp(tokens+i, json_chunk, "ymag") == 0)
				{
					++i;
					out_camera->data.orthographic.ymag = cgltf_json_to_float(tokens + i, json_chunk);
					++i;
				}
				else if (cgltf_json_strcmp(tokens+i, json_chunk, "zfar") == 0)
				{
					++i;
					out_camera->data.orthographic.zfar = cgltf_json_to_float(tokens + i, json_chunk);
					++i;
				}
				else if (cgltf_json_strcmp(tokens+i, json_chunk, "znear") == 0)
				{
					++i;
					out_camera->data.orthographic.znear = cgltf_json_to_float(tokens + i, json_chunk);
					++i;
				}
				else if (cgltf_json_strcmp(tokens + i, json_chunk, "extras") == 0)
				{
					i = cgltf_parse_json_extras(tokens, i + 1, json_chunk, &out_camera->data.orthographic.extras);
				}
				else
				{
					i = cgltf_skip_json(tokens, i+1);
				}

				if (i < 0)
				{
					return i;
				}
			}
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "extras") == 0)
		{
			i = cgltf_parse_json_extras(tokens, i + 1, json_chunk, &out_camera->extras);
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "extensions") == 0)
		{
			i = cgltf_parse_json_unprocessed_extensions(options, tokens, i, json_chunk, &out_camera->extensions_count, &out_camera->extensions);
		}
		else
		{
			i = cgltf_skip_json(tokens, i+1);
		}

		if (i < 0)
		{
			return i;
		}
	}

	return i;
}

int cgltf_parse_json_cameras(cgltf_options* options, jsmntok_t const* tokens, int i, const uint8_t* json_chunk, cgltf_data* out_data)
{
	i = cgltf_parse_json_array(options, tokens, i, json_chunk, sizeof(cgltf_camera), (void**)&out_data->cameras, &out_data->cameras_count);
	if (i < 0)
	{
		return i;
	}

	for (cgltf_size j = 0; j < out_data->cameras_count; ++j)
	{
		i = cgltf_parse_json_camera(options, tokens, i, json_chunk, &out_data->cameras[j]);
		if (i < 0)
		{
			return i;
		}
	}
	return i;
}

int cgltf_parse_json_light(cgltf_options* options, jsmntok_t const* tokens, int i, const uint8_t* json_chunk, cgltf_light* out_light)
{
	CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_OBJECT);

	int size = tokens[i].size;
	++i;

	for (int j = 0; j < size; ++j)
	{
		CGLTF_CHECK_KEY(tokens[i]);

		if (cgltf_json_strcmp(tokens+i, json_chunk, "name") == 0)
		{
			i = cgltf_parse_json_string(options, tokens, i + 1, json_chunk, &out_light->name);
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "color") == 0)
		{
			i = cgltf_parse_json_float_array(tokens, i + 1, json_chunk, out_light->color, 3);
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "intensity") == 0)
		{
			++i;
			out_light->intensity = cgltf_json_to_float(tokens + i, json_chunk);
			++i;
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "type") == 0)
		{
			++i;
			if (cgltf_json_strcmp(tokens + i, json_chunk, "directional") == 0)
			{
				out_light->type = cgltf_light_type_directional;
			}
			else if (cgltf_json_strcmp(tokens + i, json_chunk, "point") == 0)
			{
				out_light->type = cgltf_light_type_point;
			}
			else if (cgltf_json_strcmp(tokens + i, json_chunk, "spot") == 0)
			{
				out_light->type = cgltf_light_type_spot;
			}
			++i;
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "range") == 0)
		{
			++i;
			out_light->range = cgltf_json_to_float(tokens + i, json_chunk);
			++i;
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "spot") == 0)
		{
			++i;

			CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_OBJECT);

			int data_size = tokens[i].size;
			++i;

			for (int k = 0; k < data_size; ++k)
			{
				CGLTF_CHECK_KEY(tokens[i]);

				if (cgltf_json_strcmp(tokens+i, json_chunk, "innerConeAngle") == 0)
				{
					++i;
					out_light->spot_inner_cone_angle = cgltf_json_to_float(tokens + i, json_chunk);
					++i;
				}
				else if (cgltf_json_strcmp(tokens+i, json_chunk, "outerConeAngle") == 0)
				{
					++i;
					out_light->spot_outer_cone_angle = cgltf_json_to_float(tokens + i, json_chunk);
					++i;
				}
				else
				{
					i = cgltf_skip_json(tokens, i+1);
				}

				if (i < 0)
				{
					return i;
				}
			}
		}
		else
		{
			i = cgltf_skip_json(tokens, i+1);
		}

		if (i < 0)
		{
			return i;
		}
	}

	return i;
}

int cgltf_parse_json_lights(cgltf_options* options, jsmntok_t const* tokens, int i, const uint8_t* json_chunk, cgltf_data* out_data)
{
	i = cgltf_parse_json_array(options, tokens, i, json_chunk, sizeof(cgltf_light), (void**)&out_data->lights, &out_data->lights_count);
	if (i < 0)
	{
		return i;
	}

	for (cgltf_size j = 0; j < out_data->lights_count; ++j)
	{
		i = cgltf_parse_json_light(options, tokens, i, json_chunk, &out_data->lights[j]);
		if (i < 0)
		{
			return i;
		}
	}
	return i;
}

int cgltf_parse_json_node(cgltf_options* options, jsmntok_t const* tokens, int i, const uint8_t* json_chunk, cgltf_node* out_node)
{
	CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_OBJECT);

	out_node->rotation[3] = 1.0f;
	out_node->scale[0] = 1.0f;
	out_node->scale[1] = 1.0f;
	out_node->scale[2] = 1.0f;
	out_node->matrix[0] = 1.0f;
	out_node->matrix[5] = 1.0f;
	out_node->matrix[10] = 1.0f;
	out_node->matrix[15] = 1.0f;

	int size = tokens[i].size;
	++i;

	for (int j = 0; j < size; ++j)
	{
		CGLTF_CHECK_KEY(tokens[i]);

		if (cgltf_json_strcmp(tokens+i, json_chunk, "name") == 0)
		{
			i = cgltf_parse_json_string(options, tokens, i + 1, json_chunk, &out_node->name);
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "children") == 0)
		{
			i = cgltf_parse_json_array(options, tokens, i + 1, json_chunk, sizeof(cgltf_node*), (void**)&out_node->children, &out_node->children_count);
			if (i < 0)
			{
				return i;
			}

			for (cgltf_size k = 0; k < out_node->children_count; ++k)
			{
				out_node->children[k] = CGLTF_PTRINDEX(cgltf_node, cgltf_json_to_int(tokens + i, json_chunk));
				++i;
			}
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "mesh") == 0)
		{
			++i;
			CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_PRIMITIVE);
			out_node->mesh = CGLTF_PTRINDEX(cgltf_mesh, cgltf_json_to_int(tokens + i, json_chunk));
			++i;
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "skin") == 0)
		{
			++i;
			CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_PRIMITIVE);
			out_node->skin = CGLTF_PTRINDEX(cgltf_skin, cgltf_json_to_int(tokens + i, json_chunk));
			++i;
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "camera") == 0)
		{
			++i;
			CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_PRIMITIVE);
			out_node->camera = CGLTF_PTRINDEX(cgltf_camera, cgltf_json_to_int(tokens + i, json_chunk));
			++i;
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "translation") == 0)
		{
			out_node->has_translation = 1;
			i = cgltf_parse_json_float_array(tokens, i + 1, json_chunk, out_node->translation, 3);
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "rotation") == 0)
		{
			out_node->has_rotation = 1;
			i = cgltf_parse_json_float_array(tokens, i + 1, json_chunk, out_node->rotation, 4);
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "scale") == 0)
		{
			out_node->has_scale = 1;
			i = cgltf_parse_json_float_array(tokens, i + 1, json_chunk, out_node->scale, 3);
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "matrix") == 0)
		{
			out_node->has_matrix = 1;
			i = cgltf_parse_json_float_array(tokens, i + 1, json_chunk, out_node->matrix, 16);
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "weights") == 0)
		{
			i = cgltf_parse_json_array(options, tokens, i + 1, json_chunk, sizeof(cgltf_float), (void**)&out_node->weights, &out_node->weights_count);
			if (i < 0)
			{
				return i;
			}

			i = cgltf_parse_json_float_array(tokens, i - 1, json_chunk, out_node->weights, (int)out_node->weights_count);
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "extras") == 0)
		{
			i = cgltf_parse_json_extras(tokens, i + 1, json_chunk, &out_node->extras);
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "extensions") == 0)
		{
			++i;

			CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_OBJECT);
			if(out_node->extensions)
			{
				return CGLTF_ERROR_JSON;
			}

			int extensions_size = tokens[i].size;
			out_node->extensions_count= 0;
			out_node->extensions = (cgltf_extension*)cgltf_calloc(options, sizeof(cgltf_extension), extensions_size);

			if (!out_node->extensions)
			{
				return CGLTF_ERROR_NOMEM;
			}

			++i;

			for (int k = 0; k < extensions_size; ++k)
			{
				CGLTF_CHECK_KEY(tokens[i]);

				if (cgltf_json_strcmp(tokens+i, json_chunk, "KHR_lights_punctual") == 0)
				{
					++i;

					CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_OBJECT);

					int data_size = tokens[i].size;
					++i;

					for (int m = 0; m < data_size; ++m)
					{
						CGLTF_CHECK_KEY(tokens[i]);

						if (cgltf_json_strcmp(tokens + i, json_chunk, "light") == 0)
						{
							++i;
							CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_PRIMITIVE);
							out_node->light = CGLTF_PTRINDEX(cgltf_light, cgltf_json_to_int(tokens + i, json_chunk));
							++i;
						}
						else
						{
							i = cgltf_skip_json(tokens, i + 1);
						}

						if (i < 0)
						{
							return i;
						}
					}
				}
				else
				{
					i = cgltf_parse_json_unprocessed_extension(options, tokens, i, json_chunk, &(out_node->extensions[out_node->extensions_count++]));
				}

				if (i < 0)
				{
					return i;
				}
			}
		}
		else
		{
			i = cgltf_skip_json(tokens, i+1);
		}

		if (i < 0)
		{
			return i;
		}
	}

	return i;
}

int cgltf_parse_json_nodes(cgltf_options* options, jsmntok_t const* tokens, int i, const uint8_t* json_chunk, cgltf_data* out_data)
{
	i = cgltf_parse_json_array(options, tokens, i, json_chunk, sizeof(cgltf_node), (void**)&out_data->nodes, &out_data->nodes_count);
	if (i < 0)
	{
		return i;
	}

	for (cgltf_size j = 0; j < out_data->nodes_count; ++j)
	{
		i = cgltf_parse_json_node(options, tokens, i, json_chunk, &out_data->nodes[j]);
		if (i < 0)
		{
			return i;
		}
	}
	return i;
}

int cgltf_parse_json_scene(cgltf_options* options, jsmntok_t const* tokens, int i, const uint8_t* json_chunk, cgltf_scene* out_scene)
{
	CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_OBJECT);

	int size = tokens[i].size;
	++i;

	for (int j = 0; j < size; ++j)
	{
		CGLTF_CHECK_KEY(tokens[i]);

		if (cgltf_json_strcmp(tokens+i, json_chunk, "name") == 0)
		{
			i = cgltf_parse_json_string(options, tokens, i + 1, json_chunk, &out_scene->name);
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "nodes") == 0)
		{
			i = cgltf_parse_json_array(options, tokens, i + 1, json_chunk, sizeof(cgltf_node*), (void**)&out_scene->nodes, &out_scene->nodes_count);
			if (i < 0)
			{
				return i;
			}

			for (cgltf_size k = 0; k < out_scene->nodes_count; ++k)
			{
				out_scene->nodes[k] = CGLTF_PTRINDEX(cgltf_node, cgltf_json_to_int(tokens + i, json_chunk));
				++i;
			}
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "extras") == 0)
		{
			i = cgltf_parse_json_extras(tokens, i + 1, json_chunk, &out_scene->extras);
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "extensions") == 0)
		{
			i = cgltf_parse_json_unprocessed_extensions(options, tokens, i, json_chunk, &out_scene->extensions_count, &out_scene->extensions);
		}
		else
		{
			i = cgltf_skip_json(tokens, i+1);
		}

		if (i < 0)
		{
			return i;
		}
	}

	return i;
}

int cgltf_parse_json_scenes(cgltf_options* options, jsmntok_t const* tokens, int i, const uint8_t* json_chunk, cgltf_data* out_data)
{
	i = cgltf_parse_json_array(options, tokens, i, json_chunk, sizeof(cgltf_scene), (void**)&out_data->scenes, &out_data->scenes_count);
	if (i < 0)
	{
		return i;
	}

	for (cgltf_size j = 0; j < out_data->scenes_count; ++j)
	{
		i = cgltf_parse_json_scene(options, tokens, i, json_chunk, &out_data->scenes[j]);
		if (i < 0)
		{
			return i;
		}
	}
	return i;
}

int cgltf_parse_json_animation_sampler(cgltf_options* options, jsmntok_t const* tokens, int i, const uint8_t* json_chunk, cgltf_animation_sampler* out_sampler)
{
	(void)options;
	CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_OBJECT);

	int size = tokens[i].size;
	++i;

	for (int j = 0; j < size; ++j)
	{
		CGLTF_CHECK_KEY(tokens[i]);

		if (cgltf_json_strcmp(tokens+i, json_chunk, "input") == 0)
		{
			++i;
			out_sampler->input = CGLTF_PTRINDEX(cgltf_accessor, cgltf_json_to_int(tokens + i, json_chunk));
			++i;
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "output") == 0)
		{
			++i;
			out_sampler->output = CGLTF_PTRINDEX(cgltf_accessor, cgltf_json_to_int(tokens + i, json_chunk));
			++i;
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "interpolation") == 0)
		{
			++i;
			if (cgltf_json_strcmp(tokens + i, json_chunk, "LINEAR") == 0)
			{
				out_sampler->interpolation = cgltf_interpolation_type_linear;
			}
			else if (cgltf_json_strcmp(tokens + i, json_chunk, "STEP") == 0)
			{
				out_sampler->interpolation = cgltf_interpolation_type_step;
			}
			else if (cgltf_json_strcmp(tokens + i, json_chunk, "CUBICSPLINE") == 0)
			{
				out_sampler->interpolation = cgltf_interpolation_type_cubic_spline;
			}
			++i;
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "extras") == 0)
		{
			i = cgltf_parse_json_extras(tokens, i + 1, json_chunk, &out_sampler->extras);
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "extensions") == 0)
		{
			i = cgltf_parse_json_unprocessed_extensions(options, tokens, i, json_chunk, &out_sampler->extensions_count, &out_sampler->extensions);
		}
		else
		{
			i = cgltf_skip_json(tokens, i+1);
		}

		if (i < 0)
		{
			return i;
		}
	}

	return i;
}

int cgltf_parse_json_animation_channel(cgltf_options* options, jsmntok_t const* tokens, int i, const uint8_t* json_chunk, cgltf_animation_channel* out_channel)
{
	(void)options;
	CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_OBJECT);

	int size = tokens[i].size;
	++i;

	for (int j = 0; j < size; ++j)
	{
		CGLTF_CHECK_KEY(tokens[i]);

		if (cgltf_json_strcmp(tokens+i, json_chunk, "sampler") == 0)
		{
			++i;
			out_channel->sampler = CGLTF_PTRINDEX(cgltf_animation_sampler, cgltf_json_to_int(tokens + i, json_chunk));
			++i;
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "target") == 0)
		{
			++i;

			CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_OBJECT);

			int target_size = tokens[i].size;
			++i;

			for (int k = 0; k < target_size; ++k)
			{
				CGLTF_CHECK_KEY(tokens[i]);

				if (cgltf_json_strcmp(tokens+i, json_chunk, "node") == 0)
				{
					++i;
					out_channel->target_node = CGLTF_PTRINDEX(cgltf_node, cgltf_json_to_int(tokens + i, json_chunk));
					++i;
				}
				else if (cgltf_json_strcmp(tokens+i, json_chunk, "path") == 0)
				{
					++i;
					if (cgltf_json_strcmp(tokens+i, json_chunk, "translation") == 0)
					{
						out_channel->target_path = cgltf_animation_path_type_translation;
					}
					else if (cgltf_json_strcmp(tokens+i, json_chunk, "rotation") == 0)
					{
						out_channel->target_path = cgltf_animation_path_type_rotation;
					}
					else if (cgltf_json_strcmp(tokens+i, json_chunk, "scale") == 0)
					{
						out_channel->target_path = cgltf_animation_path_type_scale;
					}
					else if (cgltf_json_strcmp(tokens+i, json_chunk, "weights") == 0)
					{
						out_channel->target_path = cgltf_animation_path_type_weights;
					}
					++i;
				}
				else if (cgltf_json_strcmp(tokens + i, json_chunk, "extras") == 0)
				{
					i = cgltf_parse_json_extras(tokens, i + 1, json_chunk, &out_channel->extras);
				}
				else if (cgltf_json_strcmp(tokens + i, json_chunk, "extensions") == 0)
				{
					i = cgltf_parse_json_unprocessed_extensions(options, tokens, i, json_chunk, &out_channel->extensions_count, &out_channel->extensions);
				}
				else
				{
					i = cgltf_skip_json(tokens, i+1);
				}

				if (i < 0)
				{
					return i;
				}
			}
		}
		else
		{
			i = cgltf_skip_json(tokens, i+1);
		}

		if (i < 0)
		{
			return i;
		}
	}

	return i;
}

int cgltf_parse_json_animation(cgltf_options* options, jsmntok_t const* tokens, int i, const uint8_t* json_chunk, cgltf_animation* out_animation)
{
	CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_OBJECT);

	int size = tokens[i].size;
	++i;

	for (int j = 0; j < size; ++j)
	{
		CGLTF_CHECK_KEY(tokens[i]);

		if (cgltf_json_strcmp(tokens+i, json_chunk, "name") == 0)
		{
			i = cgltf_parse_json_string(options, tokens, i + 1, json_chunk, &out_animation->name);
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "samplers") == 0)
		{
			i = cgltf_parse_json_array(options, tokens, i + 1, json_chunk, sizeof(cgltf_animation_sampler), (void**)&out_animation->samplers, &out_animation->samplers_count);
			if (i < 0)
			{
				return i;
			}

			for (cgltf_size k = 0; k < out_animation->samplers_count; ++k)
			{
				i = cgltf_parse_json_animation_sampler(options, tokens, i, json_chunk, &out_animation->samplers[k]);
				if (i < 0)
				{
					return i;
				}
			}
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "channels") == 0)
		{
			i = cgltf_parse_json_array(options, tokens, i + 1, json_chunk, sizeof(cgltf_animation_channel), (void**)&out_animation->channels, &out_animation->channels_count);
			if (i < 0)
			{
				return i;
			}

			for (cgltf_size k = 0; k < out_animation->channels_count; ++k)
			{
				i = cgltf_parse_json_animation_channel(options, tokens, i, json_chunk, &out_animation->channels[k]);
				if (i < 0)
				{
					return i;
				}
			}
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "extras") == 0)
		{
			i = cgltf_parse_json_extras(tokens, i + 1, json_chunk, &out_animation->extras);
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "extensions") == 0)
		{
			i = cgltf_parse_json_unprocessed_extensions(options, tokens, i, json_chunk, &out_animation->extensions_count, &out_animation->extensions);
		}
		else
		{
			i = cgltf_skip_json(tokens, i+1);
		}

		if (i < 0)
		{
			return i;
		}
	}

	return i;
}

int cgltf_parse_json_animations(cgltf_options* options, jsmntok_t const* tokens, int i, const uint8_t* json_chunk, cgltf_data* out_data)
{
	i = cgltf_parse_json_array(options, tokens, i, json_chunk, sizeof(cgltf_animation), (void**)&out_data->animations, &out_data->animations_count);
	if (i < 0)
	{
		return i;
	}

	for (cgltf_size j = 0; j < out_data->animations_count; ++j)
	{
		i = cgltf_parse_json_animation(options, tokens, i, json_chunk, &out_data->animations[j]);
		if (i < 0)
		{
			return i;
		}
	}
	return i;
}

int cgltf_parse_json_variant(cgltf_options* options, jsmntok_t const* tokens, int i, const uint8_t* json_chunk, cgltf_material_variant* out_variant)
{
	CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_OBJECT);

	int size = tokens[i].size;
	++i;

	for (int j = 0; j < size; ++j)
	{
		CGLTF_CHECK_KEY(tokens[i]);

		if (cgltf_json_strcmp(tokens+i, json_chunk, "name") == 0)
		{
			i = cgltf_parse_json_string(options, tokens, i + 1, json_chunk, &out_variant->name);
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "extras") == 0)
		{
			i = cgltf_parse_json_extras(tokens, i + 1, json_chunk, &out_variant->extras);
		}
		else
		{
			i = cgltf_skip_json(tokens, i+1);
		}

		if (i < 0)
		{
			return i;
		}
	}

	return i;
}

int cgltf_parse_json_variants(cgltf_options* options, jsmntok_t const* tokens, int i, const uint8_t* json_chunk, cgltf_data* out_data)
{
	i = cgltf_parse_json_array(options, tokens, i, json_chunk, sizeof(cgltf_material_variant), (void**)&out_data->variants, &out_data->variants_count);
	if (i < 0)
	{
		return i;
	}

	for (cgltf_size j = 0; j < out_data->variants_count; ++j)
	{
		i = cgltf_parse_json_variant(options, tokens, i, json_chunk, &out_data->variants[j]);
		if (i < 0)
		{
			return i;
		}
	}
	return i;
}

int cgltf_parse_json_asset(cgltf_options* options, jsmntok_t const* tokens, int i, const uint8_t* json_chunk, cgltf_asset* out_asset)
{
	CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_OBJECT);

	int size = tokens[i].size;
	++i;

	for (int j = 0; j < size; ++j)
	{
		CGLTF_CHECK_KEY(tokens[i]);

		if (cgltf_json_strcmp(tokens+i, json_chunk, "copyright") == 0)
		{
			i = cgltf_parse_json_string(options, tokens, i + 1, json_chunk, &out_asset->copyright);
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "generator") == 0)
		{
			i = cgltf_parse_json_string(options, tokens, i + 1, json_chunk, &out_asset->generator);
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "version") == 0)
		{
			i = cgltf_parse_json_string(options, tokens, i + 1, json_chunk, &out_asset->version);
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "minVersion") == 0)
		{
			i = cgltf_parse_json_string(options, tokens, i + 1, json_chunk, &out_asset->min_version);
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "extras") == 0)
		{
			i = cgltf_parse_json_extras(tokens, i + 1, json_chunk, &out_asset->extras);
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "extensions") == 0)
		{
			i = cgltf_parse_json_unprocessed_extensions(options, tokens, i, json_chunk, &out_asset->extensions_count, &out_asset->extensions);
		}
		else
		{
			i = cgltf_skip_json(tokens, i+1);
		}

		if (i < 0)
		{
			return i;
		}
	}

	if (out_asset->version && CGLTF_ATOF(out_asset->version) < 2)
	{
		return CGLTF_ERROR_LEGACY;
	}

	return i;
}

cgltf_size cgltf_num_components(cgltf_type type) {
	switch (type)
	{
	case cgltf_type_vec2:
		return 2;
	case cgltf_type_vec3:
		return 3;
	case cgltf_type_vec4:
		return 4;
	case cgltf_type_mat2:
		return 4;
	case cgltf_type_mat3:
		return 9;
	case cgltf_type_mat4:
		return 16;
	case cgltf_type_invalid:
	case cgltf_type_scalar:
	default:
		return 1;
	}
}

cgltf_size cgltf_component_size(cgltf_component_type component_type) {
	switch (component_type)
	{
	case cgltf_component_type_r_8:
	case cgltf_component_type_r_8u:
		return 1;
	case cgltf_component_type_r_16:
	case cgltf_component_type_r_16u:
		return 2;
	case cgltf_component_type_r_32u:
	case cgltf_component_type_r_32f:
		return 4;
	case cgltf_component_type_invalid:
	default:
		return 0;
	}
}

cgltf_size cgltf_calc_size(cgltf_type type, cgltf_component_type component_type)
{
	cgltf_size component_size = cgltf_component_size(component_type);
	if (type == cgltf_type_mat2 && component_size == 1)
	{
		return 8 * component_size;
	}
	else if (type == cgltf_type_mat3 && (component_size == 1 || component_size == 2))
	{
		return 12 * component_size;
	}
	return component_size * cgltf_num_components(type);
}

int cgltf_parse_json_root(cgltf_options* options, jsmntok_t const* tokens, int i, const uint8_t* json_chunk, cgltf_data* out_data)
{
	CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_OBJECT);

	int size = tokens[i].size;
	++i;

	for (int j = 0; j < size; ++j)
	{
		CGLTF_CHECK_KEY(tokens[i]);

		if (cgltf_json_strcmp(tokens + i, json_chunk, "asset") == 0)
		{
			i = cgltf_parse_json_asset(options, tokens, i + 1, json_chunk, &out_data->asset);
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "meshes") == 0)
		{
			i = cgltf_parse_json_meshes(options, tokens, i + 1, json_chunk, out_data);
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "accessors") == 0)
		{
			i = cgltf_parse_json_accessors(options, tokens, i + 1, json_chunk, out_data);
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "bufferViews") == 0)
		{
			i = cgltf_parse_json_buffer_views(options, tokens, i + 1, json_chunk, out_data);
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "buffers") == 0)
		{
			i = cgltf_parse_json_buffers(options, tokens, i + 1, json_chunk, out_data);
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "materials") == 0)
		{
			i = cgltf_parse_json_materials(options, tokens, i + 1, json_chunk, out_data);
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "images") == 0)
		{
			i = cgltf_parse_json_images(options, tokens, i + 1, json_chunk, out_data);
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "textures") == 0)
		{
			i = cgltf_parse_json_textures(options, tokens, i + 1, json_chunk, out_data);
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "samplers") == 0)
		{
			i = cgltf_parse_json_samplers(options, tokens, i + 1, json_chunk, out_data);
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "skins") == 0)
		{
			i = cgltf_parse_json_skins(options, tokens, i + 1, json_chunk, out_data);
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "cameras") == 0)
		{
			i = cgltf_parse_json_cameras(options, tokens, i + 1, json_chunk, out_data);
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "nodes") == 0)
		{
			i = cgltf_parse_json_nodes(options, tokens, i + 1, json_chunk, out_data);
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "scenes") == 0)
		{
			i = cgltf_parse_json_scenes(options, tokens, i + 1, json_chunk, out_data);
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "scene") == 0)
		{
			++i;
			out_data->scene = CGLTF_PTRINDEX(cgltf_scene, cgltf_json_to_int(tokens + i, json_chunk));
			++i;
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "animations") == 0)
		{
			i = cgltf_parse_json_animations(options, tokens, i + 1, json_chunk, out_data);
		}
		else if (cgltf_json_strcmp(tokens+i, json_chunk, "extras") == 0)
		{
			i = cgltf_parse_json_extras(tokens, i + 1, json_chunk, &out_data->extras);
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "extensions") == 0)
		{
			++i;

			CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_OBJECT);
			if(out_data->data_extensions)
			{
				return CGLTF_ERROR_JSON;
			}

			int extensions_size = tokens[i].size;
			out_data->data_extensions_count = 0;
			out_data->data_extensions = (cgltf_extension*)cgltf_calloc(options, sizeof(cgltf_extension), extensions_size);

			if (!out_data->data_extensions)
			{
				return CGLTF_ERROR_NOMEM;
			}

			++i;

			for (int k = 0; k < extensions_size; ++k)
			{
				CGLTF_CHECK_KEY(tokens[i]);

				if (cgltf_json_strcmp(tokens+i, json_chunk, "KHR_lights_punctual") == 0)
				{
					++i;

					CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_OBJECT);

					int data_size = tokens[i].size;
					++i;

					for (int m = 0; m < data_size; ++m)
					{
						CGLTF_CHECK_KEY(tokens[i]);

						if (cgltf_json_strcmp(tokens + i, json_chunk, "lights") == 0)
						{
							i = cgltf_parse_json_lights(options, tokens, i + 1, json_chunk, out_data);
						}
						else
						{
							i = cgltf_skip_json(tokens, i + 1);
						}

						if (i < 0)
						{
							return i;
						}
					}
				}
				else if (cgltf_json_strcmp(tokens+i, json_chunk, "KHR_materials_variants") == 0)
				{
					++i;

					CGLTF_CHECK_TOKTYPE(tokens[i], JSMN_OBJECT);

					int data_size = tokens[i].size;
					++i;

					for (int m = 0; m < data_size; ++m)
					{
						CGLTF_CHECK_KEY(tokens[i]);

						if (cgltf_json_strcmp(tokens + i, json_chunk, "variants") == 0)
						{
							i = cgltf_parse_json_variants(options, tokens, i + 1, json_chunk, out_data);
						}
						else
						{
							i = cgltf_skip_json(tokens, i + 1);
						}

						if (i < 0)
						{
							return i;
						}
					}
				}
				else
				{
					i = cgltf_parse_json_unprocessed_extension(options, tokens, i, json_chunk, &(out_data->data_extensions[out_data->data_extensions_count++]));
				}

				if (i < 0)
				{
					return i;
				}
			}
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "extensionsUsed") == 0)
		{
			i = cgltf_parse_json_string_array(options, tokens, i + 1, json_chunk, &out_data->extensions_used, &out_data->extensions_used_count);
		}
		else if (cgltf_json_strcmp(tokens + i, json_chunk, "extensionsRequired") == 0)
		{
			i = cgltf_parse_json_string_array(options, tokens, i + 1, json_chunk, &out_data->extensions_required, &out_data->extensions_required_count);
		}
		else
		{
			i = cgltf_skip_json(tokens, i + 1);
		}

		if (i < 0)
		{
			return i;
		}
	}

	return i;
}

cgltf_result cgltf_parse_json(cgltf_options* options, const uint8_t* json_chunk, cgltf_size size, cgltf_data** out_data)
{
	jsmn_parser parser = { 0, 0, 0 };

	if (options->json_token_count == 0)
	{
		int token_count = jsmn_parse(&parser, (const char*)json_chunk, size, NULL, 0);

		if (token_count <= 0)
		{
			return cgltf_result_invalid_json;
		}

		options->json_token_count = token_count;
	}

	jsmntok_t* tokens = (jsmntok_t*)options->memory.alloc(options->memory.user_data, sizeof(jsmntok_t) * (options->json_token_count + 1));

	if (!tokens)
	{
		return cgltf_result_out_of_memory;
	}

	jsmn_init(&parser);

	int token_count = jsmn_parse(&parser, (const char*)json_chunk, size, tokens, options->json_token_count);

	if (token_count <= 0)
	{
		options->memory.free(options->memory.user_data, tokens);
		return cgltf_result_invalid_json;
	}

	// this makes sure that we always have an UNDEFINED token at the end of the stream
	// for invalid JSON inputs this makes sure we don't perform out of bound reads of token data
	tokens[token_count].type = JSMN_UNDEFINED;

	cgltf_data* data = (cgltf_data*)options->memory.alloc(options->memory.user_data, sizeof(cgltf_data));

	if (!data)
	{
		options->memory.free(options->memory.user_data, tokens);
		return cgltf_result_out_of_memory;
	}

	memset(data, 0, sizeof(cgltf_data));
	data->memory = options->memory;
	data->file = options->file;

	int i = cgltf_parse_json_root(options, tokens, 0, json_chunk, data);

	options->memory.free(options->memory.user_data, tokens);

	if (i < 0)
	{
		cgltf_free(data);

		switch (i)
		{
		case CGLTF_ERROR_NOMEM: return cgltf_result_out_of_memory;
		case CGLTF_ERROR_LEGACY: return cgltf_result_legacy_gltf;
		default: return cgltf_result_invalid_gltf;
		}
	}

	if (cgltf_fixup_pointers(data) < 0)
	{
		cgltf_free(data);
		return cgltf_result_invalid_gltf;
	}

	data->json = (const char*)json_chunk;
	data->json_size = size;

	*out_data = data;

	return cgltf_result_success;
}

int cgltf_fixup_pointers(cgltf_data* data)
{
	for (cgltf_size i = 0; i < data->meshes_count; ++i)
	{
		for (cgltf_size j = 0; j < data->meshes[i].primitives_count; ++j)
		{
			CGLTF_PTRFIXUP(data->meshes[i].primitives[j].indices, data->accessors, data->accessors_count);
			CGLTF_PTRFIXUP(data->meshes[i].primitives[j].material, data->materials, data->materials_count);

			for (cgltf_size k = 0; k < data->meshes[i].primitives[j].attributes_count; ++k)
			{
				CGLTF_PTRFIXUP_REQ(data->meshes[i].primitives[j].attributes[k].data, data->accessors, data->accessors_count);
			}

			for (cgltf_size k = 0; k < data->meshes[i].primitives[j].targets_count; ++k)
			{
				for (cgltf_size m = 0; m < data->meshes[i].primitives[j].targets[k].attributes_count; ++m)
				{
					CGLTF_PTRFIXUP_REQ(data->meshes[i].primitives[j].targets[k].attributes[m].data, data->accessors, data->accessors_count);
				}
			}

			if (data->meshes[i].primitives[j].has_draco_mesh_compression)
			{
				CGLTF_PTRFIXUP_REQ(data->meshes[i].primitives[j].draco_mesh_compression.buffer_view, data->buffer_views, data->buffer_views_count);
				for (cgltf_size m = 0; m < data->meshes[i].primitives[j].draco_mesh_compression.attributes_count; ++m)
				{
					CGLTF_PTRFIXUP_REQ(data->meshes[i].primitives[j].draco_mesh_compression.attributes[m].data, data->accessors, data->accessors_count);
				}
			}

			for (cgltf_size k = 0; k < data->meshes[i].primitives[j].mappings_count; ++k)
			{
				CGLTF_PTRFIXUP_REQ(data->meshes[i].primitives[j].mappings[k].material, data->materials, data->materials_count);
			}
		}
	}

	for (cgltf_size i = 0; i < data->accessors_count; ++i)
	{
		CGLTF_PTRFIXUP(data->accessors[i].buffer_view, data->buffer_views, data->buffer_views_count);

		if (data->accessors[i].is_sparse)
		{
			CGLTF_PTRFIXUP_REQ(data->accessors[i].sparse.indices_buffer_view, data->buffer_views, data->buffer_views_count);
			CGLTF_PTRFIXUP_REQ(data->accessors[i].sparse.values_buffer_view, data->buffer_views, data->buffer_views_count);
		}

		if (data->accessors[i].buffer_view)
		{
			data->accessors[i].stride = data->accessors[i].buffer_view->stride;
		}

		if (data->accessors[i].stride == 0)
		{
			data->accessors[i].stride = cgltf_calc_size(data->accessors[i].type, data->accessors[i].component_type);
		}
	}

	for (cgltf_size i = 0; i < data->textures_count; ++i)
	{
		CGLTF_PTRFIXUP(data->textures[i].image, data->images, data->images_count);
		CGLTF_PTRFIXUP(data->textures[i].basisu_image, data->images, data->images_count);
		CGLTF_PTRFIXUP(data->textures[i].sampler, data->samplers, data->samplers_count);
	}

	for (cgltf_size i = 0; i < data->images_count; ++i)
	{
		CGLTF_PTRFIXUP(data->images[i].buffer_view, data->buffer_views, data->buffer_views_count);
	}

	for (cgltf_size i = 0; i < data->materials_count; ++i)
	{
		CGLTF_PTRFIXUP(data->materials[i].normal_texture.texture, data->textures, data->textures_count);
		CGLTF_PTRFIXUP(data->materials[i].emissive_texture.texture, data->textures, data->textures_count);
		CGLTF_PTRFIXUP(data->materials[i].occlusion_texture.texture, data->textures, data->textures_count);

		CGLTF_PTRFIXUP(data->materials[i].pbr_metallic_roughness.base_color_texture.texture, data->textures, data->textures_count);
		CGLTF_PTRFIXUP(data->materials[i].pbr_metallic_roughness.metallic_roughness_texture.texture, data->textures, data->textures_count);

		CGLTF_PTRFIXUP(data->materials[i].pbr_specular_glossiness.diffuse_texture.texture, data->textures, data->textures_count);
		CGLTF_PTRFIXUP(data->materials[i].pbr_specular_glossiness.specular_glossiness_texture.texture, data->textures, data->textures_count);

		CGLTF_PTRFIXUP(data->materials[i].clearcoat.clearcoat_texture.texture, data->textures, data->textures_count);
		CGLTF_PTRFIXUP(data->materials[i].clearcoat.clearcoat_roughness_texture.texture, data->textures, data->textures_count);
		CGLTF_PTRFIXUP(data->materials[i].clearcoat.clearcoat_normal_texture.texture, data->textures, data->textures_count);

		CGLTF_PTRFIXUP(data->materials[i].specular.specular_texture.texture, data->textures, data->textures_count);
		CGLTF_PTRFIXUP(data->materials[i].specular.specular_color_texture.texture, data->textures, data->textures_count);

		CGLTF_PTRFIXUP(data->materials[i].transmission.transmission_texture.texture, data->textures, data->textures_count);

		CGLTF_PTRFIXUP(data->materials[i].volume.thickness_texture.texture, data->textures, data->textures_count);

		CGLTF_PTRFIXUP(data->materials[i].sheen.sheen_color_texture.texture, data->textures, data->textures_count);
		CGLTF_PTRFIXUP(data->materials[i].sheen.sheen_roughness_texture.texture, data->textures, data->textures_count);
	}

	for (cgltf_size i = 0; i < data->buffer_views_count; ++i)
	{
		CGLTF_PTRFIXUP_REQ(data->buffer_views[i].buffer, data->buffers, data->buffers_count);

		if (data->buffer_views[i].has_meshopt_compression)
		{
			CGLTF_PTRFIXUP_REQ(data->buffer_views[i].meshopt_compression.buffer, data->buffers, data->buffers_count);
		}
	}

	for (cgltf_size i = 0; i < data->skins_count; ++i)
	{
		for (cgltf_size j = 0; j < data->skins[i].joints_count; ++j)
		{
			CGLTF_PTRFIXUP_REQ(data->skins[i].joints[j], data->nodes, data->nodes_count);
		}

		CGLTF_PTRFIXUP(data->skins[i].skeleton, data->nodes, data->nodes_count);
		CGLTF_PTRFIXUP(data->skins[i].inverse_bind_matrices, data->accessors, data->accessors_count);
	}

	for (cgltf_size i = 0; i < data->nodes_count; ++i)
	{
		for (cgltf_size j = 0; j < data->nodes[i].children_count; ++j)
		{
			CGLTF_PTRFIXUP_REQ(data->nodes[i].children[j], data->nodes, data->nodes_count);

			if (data->nodes[i].children[j]->parent)
			{
				return CGLTF_ERROR_JSON;
			}

			data->nodes[i].children[j]->parent = &data->nodes[i];
		}

		CGLTF_PTRFIXUP(data->nodes[i].mesh, data->meshes, data->meshes_count);
		CGLTF_PTRFIXUP(data->nodes[i].skin, data->skins, data->skins_count);
		CGLTF_PTRFIXUP(data->nodes[i].camera, data->cameras, data->cameras_count);
		CGLTF_PTRFIXUP(data->nodes[i].light, data->lights, data->lights_count);
	}

	for (cgltf_size i = 0; i < data->scenes_count; ++i)
	{
		for (cgltf_size j = 0; j < data->scenes[i].nodes_count; ++j)
		{
			CGLTF_PTRFIXUP_REQ(data->scenes[i].nodes[j], data->nodes, data->nodes_count);

			if (data->scenes[i].nodes[j]->parent)
			{
				return CGLTF_ERROR_JSON;
			}
		}
	}

	CGLTF_PTRFIXUP(data->scene, data->scenes, data->scenes_count);

	for (cgltf_size i = 0; i < data->animations_count; ++i)
	{
		for (cgltf_size j = 0; j < data->animations[i].samplers_count; ++j)
		{
			CGLTF_PTRFIXUP_REQ(data->animations[i].samplers[j].input, data->accessors, data->accessors_count);
			CGLTF_PTRFIXUP_REQ(data->animations[i].samplers[j].output, data->accessors, data->accessors_count);
		}

		for (cgltf_size j = 0; j < data->animations[i].channels_count; ++j)
		{
			CGLTF_PTRFIXUP_REQ(data->animations[i].channels[j].sampler, data->animations[i].samplers, data->animations[i].samplers_count);
			CGLTF_PTRFIXUP(data->animations[i].channels[j].target_node, data->nodes, data->nodes_count);
		}
	}

	return 0;
}

void cgltf_write_indent(cgltf_write_context* context)
{
	if (context->needs_comma)
	{
		CGLTF_SPRINTF(",\n");
		context->needs_comma = 0;
	}
	else
	{
		CGLTF_SPRINTF("\n");
	}
	for (int i = 0; i < context->depth; ++i)
	{
		CGLTF_SPRINTF("%s", context->indent);
	}
}

void cgltf_write_line(cgltf_write_context* context, const char* line)
{
	if (line[0] == ']' || line[0] == '}')
	{
		--context->depth;
		context->needs_comma = 0;
	}
	cgltf_write_indent(context);
	CGLTF_SPRINTF("%s", line);
	cgltf_size last = (cgltf_size)(strlen(line) - 1);
	if (line[0] == ']' || line[0] == '}')
	{
		context->needs_comma = 1;
	}
	if (line[last] == '[' || line[last] == '{')
	{
		++context->depth;
		context->needs_comma = 0;
	}
}

void cgltf_write_strprop(cgltf_write_context* context, const char* label, const char* val)
{
	if (val)
	{
		cgltf_write_indent(context);
		CGLTF_SPRINTF("\"%s\": \"%s\"", label, val);
		context->needs_comma = 1;
	}
}

void cgltf_write_extras(cgltf_write_context* context, const cgltf_extras* extras)
{
	cgltf_size length = extras->end_offset - extras->start_offset;
	if (length > 0 && context->data->file_data)
	{
		char* json_string = ((char*) context->data->file_data) + extras->start_offset;
		cgltf_write_indent(context);
		CGLTF_SPRINTF("%s", "\"extras\": ");
		CGLTF_SNPRINTF(length, "%.*s", (int)(extras->end_offset - extras->start_offset), json_string);
		context->needs_comma = 1;
	}
}

void cgltf_write_stritem(cgltf_write_context* context, const char* item)
{
	cgltf_write_indent(context);
	CGLTF_SPRINTF("\"%s\"", item);
	context->needs_comma = 1;
}

void cgltf_write_intprop(cgltf_write_context* context, const char* label, int val, int def)
{
	if (val != def)
	{
		cgltf_write_indent(context);
		CGLTF_SPRINTF("\"%s\": %d", label, val);
		context->needs_comma = 1;
	}
}

void cgltf_write_floatprop(cgltf_write_context* context, const char* label, float val, float def)
{
	if (val != def)
	{
		cgltf_write_indent(context);
		CGLTF_SPRINTF("\"%s\": ", label);
		CGLTF_SPRINTF("%.*g", CGLTF_DECIMAL_DIG, val);
		context->needs_comma = 1;

		if (context->cursor)
		{
			char *decimal_comma = strchr(context->cursor - context->tmp, ',');
			if (decimal_comma)
			{
				*decimal_comma = '.';
			}
		}
	}
}

void cgltf_write_boolprop_optional(cgltf_write_context* context, const char* label, bool val, bool def)
{
	if (val != def)
	{
		cgltf_write_indent(context);
		CGLTF_SPRINTF("\"%s\": %s", label, val ? "true" : "false");
		context->needs_comma = 1;
	}
}

void cgltf_write_floatarrayprop(cgltf_write_context* context, const char* label, const cgltf_float* vals, cgltf_size dim)
{
	cgltf_write_indent(context);
	CGLTF_SPRINTF("\"%s\": [", label);
	for (cgltf_size i = 0; i < dim; ++i)
	{
		if (i != 0)
		{
			CGLTF_SPRINTF(", %.*g", CGLTF_DECIMAL_DIG, vals[i]);
		}
		else
		{
			CGLTF_SPRINTF("%.*g", CGLTF_DECIMAL_DIG, vals[i]);
		}
	}
	CGLTF_SPRINTF("]");
	context->needs_comma = 1;
}

bool cgltf_check_floatarray(const float* vals, int dim, float val) {
	while (dim--)
	{
		if (vals[dim] != val)
		{
			return true;
		}
	}
	return false;
}

int cgltf_int_from_component_type(cgltf_component_type ctype)
{
	switch (ctype)
	{
		case cgltf_component_type_r_8: return 5120;
		case cgltf_component_type_r_8u: return 5121;
		case cgltf_component_type_r_16: return 5122;
		case cgltf_component_type_r_16u: return 5123;
		case cgltf_component_type_r_32u: return 5125;
		case cgltf_component_type_r_32f: return 5126;
		default: return 0;
	}
}

const char* cgltf_str_from_alpha_mode(cgltf_alpha_mode alpha_mode)
{
	switch (alpha_mode)
	{
		case cgltf_alpha_mode_mask: return "MASK";
		case cgltf_alpha_mode_blend: return "BLEND";
		default: return NULL;
	}
}

const char* cgltf_str_from_type(cgltf_type type)
{
	switch (type)
	{
		case cgltf_type_scalar: return "SCALAR";
		case cgltf_type_vec2: return "VEC2";
		case cgltf_type_vec3: return "VEC3";
		case cgltf_type_vec4: return "VEC4";
		case cgltf_type_mat2: return "MAT2";
		case cgltf_type_mat3: return "MAT3";
		case cgltf_type_mat4: return "MAT4";
		default: return NULL;
	}
}

cgltf_size cgltf_dim_from_type(cgltf_type type)
{
	switch (type)
	{
		case cgltf_type_scalar: return 1;
		case cgltf_type_vec2: return 2;
		case cgltf_type_vec3: return 3;
		case cgltf_type_vec4: return 4;
		case cgltf_type_mat2: return 4;
		case cgltf_type_mat3: return 9;
		case cgltf_type_mat4: return 16;
		default: return 0;
	}
}

const char* cgltf_str_from_camera_type(cgltf_camera_type camera_type)
{
	switch (camera_type)
	{
		case cgltf_camera_type_perspective: return "perspective";
		case cgltf_camera_type_orthographic: return "orthographic";
		default: return NULL;
	}
}

const char* cgltf_str_from_light_type(cgltf_light_type light_type)
{
	switch (light_type)
	{
		case cgltf_light_type_directional: return "directional";
		case cgltf_light_type_point: return "point";
		case cgltf_light_type_spot: return "spot";
		default: return NULL;
	}
}

void cgltf_write_texture_transform(cgltf_write_context* context, const cgltf_texture_transform* transform)
{
	cgltf_write_line(context, "\"extensions\": {");
	cgltf_write_line(context, "\"KHR_texture_transform\": {");
	if (cgltf_check_floatarray(transform->offset, 2, 0.0f))
	{
		cgltf_write_floatarrayprop(context, "offset", transform->offset, 2);
	}
	cgltf_write_floatprop(context, "rotation", transform->rotation, 0.0f);
	if (cgltf_check_floatarray(transform->scale, 2, 1.0f))
	{
		cgltf_write_floatarrayprop(context, "scale", transform->scale, 2);
	}
	cgltf_write_intprop(context, "texCoord", transform->texcoord, 0);
	cgltf_write_line(context, "}");
	cgltf_write_line(context, "}");
}

void cgltf_write_asset(cgltf_write_context* context, const cgltf_asset* asset)
{
	cgltf_write_line(context, "\"asset\": {");
	cgltf_write_strprop(context, "copyright", asset->copyright);
	cgltf_write_strprop(context, "generator", asset->generator);
	cgltf_write_strprop(context, "version", asset->version);
	cgltf_write_strprop(context, "min_version", asset->min_version);
	cgltf_write_extras(context, &asset->extras);
	cgltf_write_line(context, "}");
}

void cgltf_write_primitive(cgltf_write_context* context, const cgltf_primitive* prim)
{
	cgltf_write_intprop(context, "mode", (int) prim->type, 4);
	CGLTF_WRITE_IDXPROP("indices", prim->indices, context->data->accessors);
	CGLTF_WRITE_IDXPROP("material", prim->material, context->data->materials);
	cgltf_write_line(context, "\"attributes\": {");
	for (cgltf_size i = 0; i < prim->attributes_count; ++i)
	{
		const cgltf_attribute* attr = prim->attributes + i;
		CGLTF_WRITE_IDXPROP(attr->name, attr->data, context->data->accessors);
	}
	cgltf_write_line(context, "}");

	if (prim->targets_count)
	{
		cgltf_write_line(context, "\"targets\": [");
		for (cgltf_size i = 0; i < prim->targets_count; ++i)
		{
			cgltf_write_line(context, "{");
			for (cgltf_size j = 0; j < prim->targets[i].attributes_count; ++j)
			{
				const cgltf_attribute* attr = prim->targets[i].attributes + j;
				CGLTF_WRITE_IDXPROP(attr->name, attr->data, context->data->accessors);
			}
			cgltf_write_line(context, "}");
		}
		cgltf_write_line(context, "]");
	}
	cgltf_write_extras(context, &prim->extras);

	if (prim->has_draco_mesh_compression || prim->mappings_count > 0)
	{
		cgltf_write_line(context, "\"extensions\": {");

		if (prim->has_draco_mesh_compression)
		{
			context->extension_flags |= CGLTF_EXTENSION_FLAG_DRACO_MESH_COMPRESSION;
			if (prim->attributes_count == 0 || prim->indices == 0)
			{
				context->required_extension_flags |= CGLTF_EXTENSION_FLAG_DRACO_MESH_COMPRESSION;				 
			}

			cgltf_write_line(context, "\"KHR_draco_mesh_compression\": {");
			CGLTF_WRITE_IDXPROP("bufferView", prim->draco_mesh_compression.buffer_view, context->data->buffer_views);
			cgltf_write_line(context, "\"attributes\": {");
			for (cgltf_size i = 0; i < prim->draco_mesh_compression.attributes_count; ++i)
			{
				const cgltf_attribute* attr = prim->draco_mesh_compression.attributes + i;
				CGLTF_WRITE_IDXPROP(attr->name, attr->data, context->data->accessors);
			}
			cgltf_write_line(context, "}");
			cgltf_write_line(context, "}");
		}

		if (prim->mappings_count > 0)
		{
			context->extension_flags |= CGLTF_EXTENSION_FLAG_MATERIALS_VARIANTS;
			cgltf_write_line(context, "\"KHR_materials_variants\": {");
			cgltf_write_line(context, "\"mappings\": [");
			for (cgltf_size i = 0; i < prim->mappings_count; ++i)
			{
				const cgltf_material_mapping* map = prim->mappings + i;
				cgltf_write_line(context, "{");
				CGLTF_WRITE_IDXPROP("material", map->material, context->data->materials);

				cgltf_write_indent(context);
				CGLTF_SPRINTF("\"variants\": [%d]", (int)map->variant);
				context->needs_comma = 1;

				cgltf_write_extras(context, &map->extras);
				cgltf_write_line(context, "}");
			}
			cgltf_write_line(context, "]");
			cgltf_write_line(context, "}");
		}

		cgltf_write_line(context, "}");
	}
}

void cgltf_write_mesh(cgltf_write_context* context, const cgltf_mesh* mesh)
{
	cgltf_write_line(context, "{");
	cgltf_write_strprop(context, "name", mesh->name);

	cgltf_write_line(context, "\"primitives\": [");
	for (cgltf_size i = 0; i < mesh->primitives_count; ++i)
	{
		cgltf_write_line(context, "{");
		cgltf_write_primitive(context, mesh->primitives + i);
		cgltf_write_line(context, "}");
	}
	cgltf_write_line(context, "]");

	if (mesh->weights_count > 0)
	{
		cgltf_write_floatarrayprop(context, "weights", mesh->weights, mesh->weights_count);
	}
	cgltf_write_extras(context, &mesh->extras);
	cgltf_write_line(context, "}");
}

void cgltf_write_buffer_view(cgltf_write_context* context, const cgltf_buffer_view* view)
{
	cgltf_write_line(context, "{");
	cgltf_write_strprop(context, "name", view->name);
	CGLTF_WRITE_IDXPROP("buffer", view->buffer, context->data->buffers);
	cgltf_write_intprop(context, "byteLength", (int)view->size, -1);
	cgltf_write_intprop(context, "byteOffset", (int)view->offset, 0);
	cgltf_write_intprop(context, "byteStride", (int)view->stride, 0);
	// NOTE: We skip writing "target" because the spec says its usage can be inferred.
	cgltf_write_extras(context, &view->extras);
	cgltf_write_line(context, "}");
}


void cgltf_write_buffer(cgltf_write_context* context, const cgltf_buffer* buffer)
{
	cgltf_write_line(context, "{");
	cgltf_write_strprop(context, "name", buffer->name);
	cgltf_write_strprop(context, "uri", buffer->uri);
	cgltf_write_intprop(context, "byteLength", (int)buffer->size, -1);
	cgltf_write_extras(context, &buffer->extras);
	cgltf_write_line(context, "}");
}

void cgltf_write_material(cgltf_write_context* context, const cgltf_material* material)
{
	cgltf_write_line(context, "{");
	cgltf_write_strprop(context, "name", material->name);
	cgltf_write_floatprop(context, "alphaCutoff", material->alpha_cutoff, 0.5f);
	cgltf_write_boolprop_optional(context, "doubleSided", material->double_sided, false);
	// cgltf_write_boolprop_optional(context, "unlit", material->unlit, false);

	if (material->unlit)
	{
		context->extension_flags |= CGLTF_EXTENSION_FLAG_MATERIALS_UNLIT;
	}

	if (material->has_pbr_specular_glossiness)
	{
		context->extension_flags |= CGLTF_EXTENSION_FLAG_SPECULAR_GLOSSINESS;
	}

	if (material->has_clearcoat)
	{
		context->extension_flags |= CGLTF_EXTENSION_FLAG_MATERIALS_CLEARCOAT;
	}

	if (material->has_transmission)
	{
		context->extension_flags |= CGLTF_EXTENSION_FLAG_MATERIALS_TRANSMISSION;
	}

	if (material->has_volume)
	{
		context->extension_flags |= CGLTF_EXTENSION_FLAG_MATERIALS_VOLUME;
	}

	if (material->has_ior)
	{
		context->extension_flags |= CGLTF_EXTENSION_FLAG_MATERIALS_IOR;
	}

	if (material->has_specular)
	{
		context->extension_flags |= CGLTF_EXTENSION_FLAG_MATERIALS_SPECULAR;
	}

	if (material->has_sheen)
	{
		context->extension_flags |= CGLTF_EXTENSION_FLAG_MATERIALS_SHEEN;
	}

	if (material->has_pbr_metallic_roughness)
	{
		const cgltf_pbr_metallic_roughness* params = &material->pbr_metallic_roughness;
		cgltf_write_line(context, "\"pbrMetallicRoughness\": {");
		CGLTF_WRITE_TEXTURE_INFO("baseColorTexture", params->base_color_texture);
		CGLTF_WRITE_TEXTURE_INFO("metallicRoughnessTexture", params->metallic_roughness_texture);
		cgltf_write_floatprop(context, "metallicFactor", params->metallic_factor, 1.0f);
		cgltf_write_floatprop(context, "roughnessFactor", params->roughness_factor, 1.0f);
		if (cgltf_check_floatarray(params->base_color_factor, 4, 1.0f))
		{
			cgltf_write_floatarrayprop(context, "baseColorFactor", params->base_color_factor, 4);
		}
		cgltf_write_extras(context, &params->extras);
		cgltf_write_line(context, "}");
	}

	if (material->unlit || material->has_pbr_specular_glossiness || material->has_clearcoat || material->has_ior || material->has_specular || material->has_transmission || material->has_sheen || material->has_volume)
	{
		cgltf_write_line(context, "\"extensions\": {");
		if (material->has_clearcoat)
		{
			const cgltf_clearcoat* params = &material->clearcoat;
			cgltf_write_line(context, "\"KHR_materials_clearcoat\": {");
			CGLTF_WRITE_TEXTURE_INFO("clearcoatTexture", params->clearcoat_texture);
			CGLTF_WRITE_TEXTURE_INFO("clearcoatRoughnessTexture", params->clearcoat_roughness_texture);
			CGLTF_WRITE_TEXTURE_INFO("clearcoatNormalTexture", params->clearcoat_normal_texture);
			cgltf_write_floatprop(context, "clearcoatFactor", params->clearcoat_factor, 0.0f);
			cgltf_write_floatprop(context, "clearcoatRoughnessFactor", params->clearcoat_roughness_factor, 0.0f);
			cgltf_write_line(context, "}");
		}
		if (material->has_ior)
		{
			const cgltf_ior* params = &material->ior;
			cgltf_write_line(context, "\"KHR_materials_ior\": {");
			cgltf_write_floatprop(context, "ior", params->ior, 1.5f);
			cgltf_write_line(context, "}");
		}
		if (material->has_specular)
		{
			const cgltf_specular* params = &material->specular;
			cgltf_write_line(context, "\"KHR_materials_specular\": {");
			CGLTF_WRITE_TEXTURE_INFO("specularTexture", params->specular_texture);
			CGLTF_WRITE_TEXTURE_INFO("specularColorTexture", params->specular_color_texture);
			cgltf_write_floatprop(context, "specularFactor", params->specular_factor, 1.0f);
			if (cgltf_check_floatarray(params->specular_color_factor, 3, 1.0f))
			{
				cgltf_write_floatarrayprop(context, "specularColorFactor", params->specular_color_factor, 3);
			}
			cgltf_write_line(context, "}");
		}
		if (material->has_transmission)
		{
			const cgltf_transmission* params = &material->transmission;
			cgltf_write_line(context, "\"KHR_materials_transmission\": {");
			CGLTF_WRITE_TEXTURE_INFO("transmissionTexture", params->transmission_texture);
			cgltf_write_floatprop(context, "transmissionFactor", params->transmission_factor, 0.0f);
			cgltf_write_line(context, "}");
		}
		if (material->has_volume)
		{
			const cgltf_volume* params = &material->volume;
			cgltf_write_line(context, "\"KHR_materials_volume\": {");
			CGLTF_WRITE_TEXTURE_INFO("thicknessTexture", params->thickness_texture);
			cgltf_write_floatprop(context, "thicknessFactor", params->thickness_factor, 0.0f);
			if (cgltf_check_floatarray(params->attenuation_color, 3, 1.0f))
			{
				cgltf_write_floatarrayprop(context, "attenuationColor", params->attenuation_color, 3);
			}
			if (params->attenuation_distance < FLT_MAX) 
			{
				cgltf_write_floatprop(context, "attenuationDistance", params->attenuation_distance, FLT_MAX);
			}
			cgltf_write_line(context, "}");
		}
		if (material->has_sheen)
		{
			const cgltf_sheen* params = &material->sheen;
			cgltf_write_line(context, "\"KHR_materials_sheen\": {");
			CGLTF_WRITE_TEXTURE_INFO("sheenColorTexture", params->sheen_color_texture);
			CGLTF_WRITE_TEXTURE_INFO("sheenRoughnessTexture", params->sheen_roughness_texture);
			if (cgltf_check_floatarray(params->sheen_color_factor, 3, 0.0f))
			{
				cgltf_write_floatarrayprop(context, "sheenColorFactor", params->sheen_color_factor, 3);
			}
			cgltf_write_floatprop(context, "sheenRoughnessFactor", params->sheen_roughness_factor, 0.0f);
			cgltf_write_line(context, "}");
		}
		if (material->has_pbr_specular_glossiness)
		{
			const cgltf_pbr_specular_glossiness* params = &material->pbr_specular_glossiness;
			cgltf_write_line(context, "\"KHR_materials_pbrSpecularGlossiness\": {");
			CGLTF_WRITE_TEXTURE_INFO("diffuseTexture", params->diffuse_texture);
			CGLTF_WRITE_TEXTURE_INFO("specularGlossinessTexture", params->specular_glossiness_texture);
			if (cgltf_check_floatarray(params->diffuse_factor, 4, 1.0f))
			{
				cgltf_write_floatarrayprop(context, "dffuseFactor", params->diffuse_factor, 4);
			}
			if (cgltf_check_floatarray(params->specular_factor, 3, 1.0f))
			{
				cgltf_write_floatarrayprop(context, "specularFactor", params->specular_factor, 3);
			}
			cgltf_write_floatprop(context, "glossinessFactor", params->glossiness_factor, 1.0f);
			cgltf_write_line(context, "}");
		}
		if (material->unlit)
		{
			cgltf_write_line(context, "\"KHR_materials_unlit\": {}");
		}
		cgltf_write_line(context, "}");
	}

	CGLTF_WRITE_TEXTURE_INFO("normalTexture", material->normal_texture);
	CGLTF_WRITE_TEXTURE_INFO("occlusionTexture", material->occlusion_texture);
	CGLTF_WRITE_TEXTURE_INFO("emissiveTexture", material->emissive_texture);
	if (cgltf_check_floatarray(material->emissive_factor, 3, 0.0f))
	{
		cgltf_write_floatarrayprop(context, "emissiveFactor", material->emissive_factor, 3);
	}
	cgltf_write_strprop(context, "alphaMode", cgltf_str_from_alpha_mode(material->alpha_mode));
	cgltf_write_extras(context, &material->extras);
	cgltf_write_line(context, "}");
}

void cgltf_write_image(cgltf_write_context* context, const cgltf_image* image)
{
	cgltf_write_line(context, "{");
	cgltf_write_strprop(context, "name", image->name);
	cgltf_write_strprop(context, "uri", image->uri);
	CGLTF_WRITE_IDXPROP("bufferView", image->buffer_view, context->data->buffer_views);
	cgltf_write_strprop(context, "mimeType", image->mime_type);
	cgltf_write_extras(context, &image->extras);
	cgltf_write_line(context, "}");
}

void cgltf_write_texture(cgltf_write_context* context, const cgltf_texture* texture)
{
	cgltf_write_line(context, "{");
	cgltf_write_strprop(context, "name", texture->name);
	CGLTF_WRITE_IDXPROP("source", texture->image, context->data->images);
	CGLTF_WRITE_IDXPROP("sampler", texture->sampler, context->data->samplers);

	if (texture->has_basisu)
	{
		cgltf_write_line(context, "\"extensions\": {");
		{
			context->extension_flags |= CGLTF_EXTENSION_FLAG_TEXTURE_BASISU;
			cgltf_write_line(context, "\"KHR_texture_basisu\": {");
			CGLTF_WRITE_IDXPROP("source", texture->basisu_image, context->data->images);
			cgltf_write_line(context, "}");
		}
		cgltf_write_line(context, "}");
	}
	cgltf_write_extras(context, &texture->extras);
	cgltf_write_line(context, "}");
}

void cgltf_write_skin(cgltf_write_context* context, const cgltf_skin* skin)
{
	cgltf_write_line(context, "{");
	CGLTF_WRITE_IDXPROP("skeleton", skin->skeleton, context->data->nodes);
	CGLTF_WRITE_IDXPROP("inverseBindMatrices", skin->inverse_bind_matrices, context->data->accessors);
	CGLTF_WRITE_IDXARRPROP("joints", skin->joints_count, skin->joints, context->data->nodes);
	cgltf_write_strprop(context, "name", skin->name);
	cgltf_write_extras(context, &skin->extras);
	cgltf_write_line(context, "}");
}

const char* cgltf_write_str_path_type(cgltf_animation_path_type path_type)
{
	switch (path_type)
	{
	case cgltf_animation_path_type_translation:
		return "translation";
	case cgltf_animation_path_type_rotation:
		return "rotation";
	case cgltf_animation_path_type_scale:
		return "scale";
	case cgltf_animation_path_type_weights:
		return "weights";
	case cgltf_animation_path_type_invalid:
		break;
	}
	return "invalid";
}

const char* cgltf_write_str_interpolation_type(cgltf_interpolation_type interpolation_type)
{
	switch (interpolation_type)
	{
	case cgltf_interpolation_type_linear:
		return "LINEAR";
	case cgltf_interpolation_type_step:
		return "STEP";
	case cgltf_interpolation_type_cubic_spline:
		return "CUBICSPLINE";
	}
	return "invalid";
}

void cgltf_write_path_type(cgltf_write_context* context, const char *label, cgltf_animation_path_type path_type)
{
	cgltf_write_strprop(context, label, cgltf_write_str_path_type(path_type));
}

void cgltf_write_interpolation_type(cgltf_write_context* context, const char *label, cgltf_interpolation_type interpolation_type)
{
	cgltf_write_strprop(context, label, cgltf_write_str_interpolation_type(interpolation_type));
}

void cgltf_write_animation_sampler(cgltf_write_context* context, const cgltf_animation_sampler* animation_sampler)
{
	cgltf_write_line(context, "{");
	cgltf_write_interpolation_type(context, "interpolation", animation_sampler->interpolation);
	CGLTF_WRITE_IDXPROP("input", animation_sampler->input, context->data->accessors);
	CGLTF_WRITE_IDXPROP("output", animation_sampler->output, context->data->accessors);
	cgltf_write_extras(context, &animation_sampler->extras);
	cgltf_write_line(context, "}");
}

void cgltf_write_animation_channel(cgltf_write_context* context, const cgltf_animation* animation, const cgltf_animation_channel* animation_channel)
{
	cgltf_write_line(context, "{");
	CGLTF_WRITE_IDXPROP("sampler", animation_channel->sampler, animation->samplers);
	cgltf_write_line(context, "\"target\": {");
	CGLTF_WRITE_IDXPROP("node", animation_channel->target_node, context->data->nodes);
	cgltf_write_path_type(context, "path", animation_channel->target_path);
	cgltf_write_line(context, "}");
	cgltf_write_extras(context, &animation_channel->extras);
	cgltf_write_line(context, "}");
}

void cgltf_write_animation(cgltf_write_context* context, const cgltf_animation* animation)
{
	cgltf_write_line(context, "{");
	cgltf_write_strprop(context, "name", animation->name);

	if (animation->samplers_count > 0)
	{
		cgltf_write_line(context, "\"samplers\": [");
		for (cgltf_size i = 0; i < animation->samplers_count; ++i)
		{
			cgltf_write_animation_sampler(context, animation->samplers + i);
		}
		cgltf_write_line(context, "]");
	}
	if (animation->channels_count > 0)
	{
		cgltf_write_line(context, "\"channels\": [");
		for (cgltf_size i = 0; i < animation->channels_count; ++i)
		{
			cgltf_write_animation_channel(context, animation, animation->channels + i);
		}
		cgltf_write_line(context, "]");
	}
	cgltf_write_extras(context, &animation->extras);
	cgltf_write_line(context, "}");
}

void cgltf_write_sampler(cgltf_write_context* context, const cgltf_sampler* sampler)
{
	cgltf_write_line(context, "{");
	cgltf_write_strprop(context, "name", sampler->name);
	cgltf_write_intprop(context, "magFilter", sampler->mag_filter, 0);
	cgltf_write_intprop(context, "minFilter", sampler->min_filter, 0);
	cgltf_write_intprop(context, "wrapS", sampler->wrap_s, 10497);
	cgltf_write_intprop(context, "wrapT", sampler->wrap_t, 10497);
	cgltf_write_extras(context, &sampler->extras);
	cgltf_write_line(context, "}");
}

void cgltf_write_node(cgltf_write_context* context, const cgltf_node* node)
{
	cgltf_write_line(context, "{");
	CGLTF_WRITE_IDXARRPROP("children", node->children_count, node->children, context->data->nodes);
	CGLTF_WRITE_IDXPROP("mesh", node->mesh, context->data->meshes);
	cgltf_write_strprop(context, "name", node->name);
	if (node->has_matrix)
	{
		cgltf_write_floatarrayprop(context, "matrix", node->matrix, 16);
	}
	if (node->has_translation)
	{
		cgltf_write_floatarrayprop(context, "translation", node->translation, 3);
	}
	if (node->has_rotation)
	{
		cgltf_write_floatarrayprop(context, "rotation", node->rotation, 4);
	}
	if (node->has_scale)
	{
		cgltf_write_floatarrayprop(context, "scale", node->scale, 3);
	}
	if (node->skin)
	{
		CGLTF_WRITE_IDXPROP("skin", node->skin, context->data->skins);
	}

	if (node->light)
	{
		context->extension_flags |= CGLTF_EXTENSION_FLAG_LIGHTS_PUNCTUAL;
		cgltf_write_line(context, "\"extensions\": {");
		cgltf_write_line(context, "\"KHR_lights_punctual\": {");
		CGLTF_WRITE_IDXPROP("light", node->light, context->data->lights);
		cgltf_write_line(context, "}");
		cgltf_write_line(context, "}");
	}

	if (node->weights_count > 0)
	{
		cgltf_write_floatarrayprop(context, "weights", node->weights, node->weights_count);
	}

	if (node->camera)
	{
		CGLTF_WRITE_IDXPROP("camera", node->camera, context->data->cameras);
	}

	cgltf_write_extras(context, &node->extras);
	cgltf_write_line(context, "}");
}

void cgltf_write_scene(cgltf_write_context* context, const cgltf_scene* scene)
{
	cgltf_write_line(context, "{");
	cgltf_write_strprop(context, "name", scene->name);
	CGLTF_WRITE_IDXARRPROP("nodes", scene->nodes_count, scene->nodes, context->data->nodes);
	cgltf_write_extras(context, &scene->extras);
	cgltf_write_line(context, "}");
}

void cgltf_write_accessor(cgltf_write_context* context, const cgltf_accessor* accessor)
{
	cgltf_write_line(context, "{");
	cgltf_write_strprop(context, "name", accessor->name);
	CGLTF_WRITE_IDXPROP("bufferView", accessor->buffer_view, context->data->buffer_views);
	cgltf_write_intprop(context, "componentType", cgltf_int_from_component_type(accessor->component_type), 0);
	cgltf_write_strprop(context, "type", cgltf_str_from_type(accessor->type));
	cgltf_size dim = cgltf_dim_from_type(accessor->type);
	cgltf_write_boolprop_optional(context, "normalized", accessor->normalized, false);
	cgltf_write_intprop(context, "byteOffset", (int)accessor->offset, 0);
	cgltf_write_intprop(context, "count", (int)accessor->count, -1);
	if (accessor->has_min)
	{
		cgltf_write_floatarrayprop(context, "min", accessor->min, dim);
	}
	if (accessor->has_max)
	{
		cgltf_write_floatarrayprop(context, "max", accessor->max, dim);
	}
	if (accessor->is_sparse)
	{
		cgltf_write_line(context, "\"sparse\": {");
		cgltf_write_intprop(context, "count", (int)accessor->sparse.count, 0);
		cgltf_write_line(context, "\"indices\": {");
		cgltf_write_intprop(context, "byteOffset", (int)accessor->sparse.indices_byte_offset, 0);
		CGLTF_WRITE_IDXPROP("bufferView", accessor->sparse.indices_buffer_view, context->data->buffer_views);
		cgltf_write_intprop(context, "componentType", cgltf_int_from_component_type(accessor->sparse.indices_component_type), 0);
		cgltf_write_extras(context, &accessor->sparse.indices_extras);
		cgltf_write_line(context, "}");
		cgltf_write_line(context, "\"values\": {");
		cgltf_write_intprop(context, "byteOffset", (int)accessor->sparse.values_byte_offset, 0);
		CGLTF_WRITE_IDXPROP("bufferView", accessor->sparse.values_buffer_view, context->data->buffer_views);
		cgltf_write_extras(context, &accessor->sparse.values_extras);
		cgltf_write_line(context, "}");
		cgltf_write_extras(context, &accessor->sparse.extras);
		cgltf_write_line(context, "}");
	}
	cgltf_write_extras(context, &accessor->extras);
	cgltf_write_line(context, "}");
}

void cgltf_write_camera(cgltf_write_context* context, const cgltf_camera* camera)
{
	cgltf_write_line(context, "{");
	cgltf_write_strprop(context, "type", cgltf_str_from_camera_type(camera->type));
	if (camera->name)
	{
		cgltf_write_strprop(context, "name", camera->name);
	}

	if (camera->type == cgltf_camera_type_orthographic)
	{
		cgltf_write_line(context, "\"orthographic\": {");
		cgltf_write_floatprop(context, "xmag", camera->data.orthographic.xmag, -1.0f);
		cgltf_write_floatprop(context, "ymag", camera->data.orthographic.ymag, -1.0f);
		cgltf_write_floatprop(context, "zfar", camera->data.orthographic.zfar, -1.0f);
		cgltf_write_floatprop(context, "znear", camera->data.orthographic.znear, -1.0f);
		cgltf_write_extras(context, &camera->data.orthographic.extras);
		cgltf_write_line(context, "}");
	}
	else if (camera->type == cgltf_camera_type_perspective)
	{
		cgltf_write_line(context, "\"perspective\": {");

		if (camera->data.perspective.has_aspect_ratio) {
			cgltf_write_floatprop(context, "aspectRatio", camera->data.perspective.aspect_ratio, -1.0f);
		}

		cgltf_write_floatprop(context, "yfov", camera->data.perspective.yfov, -1.0f);

		if (camera->data.perspective.has_zfar) {
			cgltf_write_floatprop(context, "zfar", camera->data.perspective.zfar, -1.0f);
		}

		cgltf_write_floatprop(context, "znear", camera->data.perspective.znear, -1.0f);
		cgltf_write_extras(context, &camera->data.perspective.extras);
		cgltf_write_line(context, "}");
	}
	cgltf_write_extras(context, &camera->extras);
	cgltf_write_line(context, "}");
}

void cgltf_write_light(cgltf_write_context* context, const cgltf_light* light)
{
	context->extension_flags |= CGLTF_EXTENSION_FLAG_LIGHTS_PUNCTUAL;

	cgltf_write_line(context, "{");
	cgltf_write_strprop(context, "type", cgltf_str_from_light_type(light->type));
	if (light->name)
	{
		cgltf_write_strprop(context, "name", light->name);
	}
	if (cgltf_check_floatarray(light->color, 3, 1.0f))
	{
		cgltf_write_floatarrayprop(context, "color", light->color, 3);
	}
	cgltf_write_floatprop(context, "intensity", light->intensity, 1.0f);
	cgltf_write_floatprop(context, "range", light->range, 0.0f);

	if (light->type == cgltf_light_type_spot)
	{
		cgltf_write_line(context, "\"spot\": {");
		cgltf_write_floatprop(context, "innerConeAngle", light->spot_inner_cone_angle, 0.0f);
		cgltf_write_floatprop(context, "outerConeAngle", light->spot_outer_cone_angle, 3.14159265358979323846f/4.0f);
		cgltf_write_line(context, "}");
	}
	cgltf_write_line(context, "}");
}

void cgltf_write_variant(cgltf_write_context* context, const cgltf_material_variant* variant)
{
	context->extension_flags |= CGLTF_EXTENSION_FLAG_MATERIALS_VARIANTS;

	cgltf_write_line(context, "{");
	cgltf_write_strprop(context, "name", variant->name);
	cgltf_write_extras(context, &variant->extras);
	cgltf_write_line(context, "}");
}

cgltf_result cgltf_write_file(const cgltf_options* options, const char* path, const cgltf_data* data)
{
	cgltf_size expected = cgltf_write(options, NULL, 0, data);
	char* buffer = (char*) malloc(expected);
	cgltf_size actual = cgltf_write(options, buffer, expected, data);
	if (expected != actual) {
		fprintf(stderr, "Error: expected %zu bytes but wrote %zu bytes.\n", expected, actual);
	}
	FILE* file = fopen(path, "wt");
	if (!file)
	{
		return cgltf_result_file_not_found;
	}
	// Note that cgltf_write() includes a null terminator, which we omit from the file content.
	fwrite(buffer, actual - 1, 1, file);
	fclose(file);
	free(buffer);
	return cgltf_result_success;
}

void cgltf_write_extensions(cgltf_write_context* context, uint32_t extension_flags)
{
	if (extension_flags & CGLTF_EXTENSION_FLAG_TEXTURE_TRANSFORM) {
		cgltf_write_stritem(context, "KHR_texture_transform");
	}
	if (extension_flags & CGLTF_EXTENSION_FLAG_MATERIALS_UNLIT) {
		cgltf_write_stritem(context, "KHR_materials_unlit");
	}
	if (extension_flags & CGLTF_EXTENSION_FLAG_SPECULAR_GLOSSINESS) {
		cgltf_write_stritem(context, "KHR_materials_pbrSpecularGlossiness");
	}
	if (extension_flags & CGLTF_EXTENSION_FLAG_LIGHTS_PUNCTUAL) {
		cgltf_write_stritem(context, "KHR_lights_punctual");
	}
	if (extension_flags & CGLTF_EXTENSION_FLAG_DRACO_MESH_COMPRESSION) {
		cgltf_write_stritem(context, "KHR_draco_mesh_compression");
	}
	if (extension_flags & CGLTF_EXTENSION_FLAG_MATERIALS_CLEARCOAT) {
		cgltf_write_stritem(context, "KHR_materials_clearcoat");
	}
	if (extension_flags & CGLTF_EXTENSION_FLAG_MATERIALS_IOR) {
		cgltf_write_stritem(context, "KHR_materials_ior");
	}
	if (extension_flags & CGLTF_EXTENSION_FLAG_MATERIALS_SPECULAR) {
		cgltf_write_stritem(context, "KHR_materials_specular");
	}
	if (extension_flags & CGLTF_EXTENSION_FLAG_MATERIALS_TRANSMISSION) {
		cgltf_write_stritem(context, "KHR_materials_transmission");
	}
	if (extension_flags & CGLTF_EXTENSION_FLAG_MATERIALS_SHEEN) {
		cgltf_write_stritem(context, "KHR_materials_sheen");
	}
	if (extension_flags & CGLTF_EXTENSION_FLAG_MATERIALS_VARIANTS) {
		cgltf_write_stritem(context, "KHR_materials_variants");
	}
	if (extension_flags & CGLTF_EXTENSION_FLAG_MATERIALS_VOLUME) {
		cgltf_write_stritem(context, "KHR_materials_volume");
	}
	if (extension_flags & CGLTF_EXTENSION_FLAG_TEXTURE_BASISU) {
		cgltf_write_stritem(context, "KHR_texture_basisu");
	}
}

cgltf_size cgltf_write(const cgltf_options* options, char* buffer, cgltf_size size, const cgltf_data* data)
{
	(void)options;
	cgltf_write_context ctx;
	ctx.buffer = buffer;
	ctx.buffer_size = size;
	ctx.remaining = size;
	ctx.cursor = buffer;
	ctx.chars_written = 0;
	ctx.data = data;
	ctx.depth = 1;
	ctx.indent = "  ";
	ctx.needs_comma = 0;
	ctx.extension_flags = 0;
	ctx.required_extension_flags = 0;

	cgltf_write_context* context = &ctx;

	CGLTF_SPRINTF("{");

	if (data->accessors_count > 0)
	{
		cgltf_write_line(context, "\"accessors\": [");
		for (cgltf_size i = 0; i < data->accessors_count; ++i)
		{
			cgltf_write_accessor(context, data->accessors + i);
		}
		cgltf_write_line(context, "]");
	}

	cgltf_write_asset(context, &data->asset);

	if (data->buffer_views_count > 0)
	{
		cgltf_write_line(context, "\"bufferViews\": [");
		for (cgltf_size i = 0; i < data->buffer_views_count; ++i)
		{
			cgltf_write_buffer_view(context, data->buffer_views + i);
		}
		cgltf_write_line(context, "]");
	}

	if (data->buffers_count > 0)
	{
		cgltf_write_line(context, "\"buffers\": [");
		for (cgltf_size i = 0; i < data->buffers_count; ++i)
		{
			cgltf_write_buffer(context, data->buffers + i);
		}
		cgltf_write_line(context, "]");
	}

	if (data->images_count > 0)
	{
		cgltf_write_line(context, "\"images\": [");
		for (cgltf_size i = 0; i < data->images_count; ++i)
		{
			cgltf_write_image(context, data->images + i);
		}
		cgltf_write_line(context, "]");
	}

	if (data->meshes_count > 0)
	{
		cgltf_write_line(context, "\"meshes\": [");
		for (cgltf_size i = 0; i < data->meshes_count; ++i)
		{
			cgltf_write_mesh(context, data->meshes + i);
		}
		cgltf_write_line(context, "]");
	}

	if (data->materials_count > 0)
	{
		cgltf_write_line(context, "\"materials\": [");
		for (cgltf_size i = 0; i < data->materials_count; ++i)
		{
			cgltf_write_material(context, data->materials + i);
		}
		cgltf_write_line(context, "]");
	}

	if (data->nodes_count > 0)
	{
		cgltf_write_line(context, "\"nodes\": [");
		for (cgltf_size i = 0; i < data->nodes_count; ++i)
		{
			cgltf_write_node(context, data->nodes + i);
		}
		cgltf_write_line(context, "]");
	}

	if (data->samplers_count > 0)
	{
		cgltf_write_line(context, "\"samplers\": [");
		for (cgltf_size i = 0; i < data->samplers_count; ++i)
		{
			cgltf_write_sampler(context, data->samplers + i);
		}
		cgltf_write_line(context, "]");
	}

	CGLTF_WRITE_IDXPROP("scene", data->scene, data->scenes);

	if (data->scenes_count > 0)
	{
		cgltf_write_line(context, "\"scenes\": [");
		for (cgltf_size i = 0; i < data->scenes_count; ++i)
		{
			cgltf_write_scene(context, data->scenes + i);
		}
		cgltf_write_line(context, "]");
	}

	if (data->textures_count > 0)
	{
		cgltf_write_line(context, "\"textures\": [");
		for (cgltf_size i = 0; i < data->textures_count; ++i)
		{
			cgltf_write_texture(context, data->textures + i);
		}
		cgltf_write_line(context, "]");
	}

	if (data->skins_count > 0)
	{
		cgltf_write_line(context, "\"skins\": [");
		for (cgltf_size i = 0; i < data->skins_count; ++i)
		{
			cgltf_write_skin(context, data->skins + i);
		}
		cgltf_write_line(context, "]");
	}

	if (data->animations_count > 0)
	{
		cgltf_write_line(context, "\"animations\": [");
		for (cgltf_size i = 0; i < data->animations_count; ++i)
		{
			cgltf_write_animation(context, data->animations + i);
		}
		cgltf_write_line(context, "]");
	}

	if (data->cameras_count > 0)
	{
		cgltf_write_line(context, "\"cameras\": [");
		for (cgltf_size i = 0; i < data->cameras_count; ++i)
		{
			cgltf_write_camera(context, data->cameras + i);
		}
		cgltf_write_line(context, "]");
	}

	if (data->lights_count > 0 || data->variants_count > 0)
	{
		cgltf_write_line(context, "\"extensions\": {");

		if (data->lights_count > 0)
		{
			cgltf_write_line(context, "\"KHR_lights_punctual\": {");
			cgltf_write_line(context, "\"lights\": [");
			for (cgltf_size i = 0; i < data->lights_count; ++i)
			{
				cgltf_write_light(context, data->lights + i);
			}
			cgltf_write_line(context, "]");
			cgltf_write_line(context, "}");
		}

		if (data->variants_count)
		{
			cgltf_write_line(context, "\"KHR_materials_variants\": {");
			cgltf_write_line(context, "\"variants\": [");
			for (cgltf_size i = 0; i < data->variants_count; ++i)
			{
				cgltf_write_variant(context, data->variants + i);
			}
			cgltf_write_line(context, "]");
			cgltf_write_line(context, "}");
		}

		cgltf_write_line(context, "}");
	}

	if (context->extension_flags != 0)
	{
		cgltf_write_line(context, "\"extensionsUsed\": [");
		cgltf_write_extensions(context, context->extension_flags);
		cgltf_write_line(context, "]");
	}

	if (context->required_extension_flags != 0)
	{
		cgltf_write_line(context, "\"extensionsRequired\": [");
		cgltf_write_extensions(context, context->required_extension_flags);
		cgltf_write_line(context, "]");
	}

	cgltf_write_extras(context, &data->extras);

	CGLTF_SPRINTF("\n}\n");

	// snprintf does not include the null terminator in its return value, so be sure to include it
	// in the returned byte count.
	return 1 + ctx.chars_written;
}

/* cgltf is distributed under MIT license:
 *
 * Copyright (c) 2019 Philip Rideout

 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:

 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.

 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */