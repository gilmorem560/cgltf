/**
 * cgltf - a glTF 2.0 library written in C99.
 *
 * Version: 1.11
 *
 * Website: https://github.com/gilmorem560/cgltf
 *
 * Distributed under the MIT License, see notice at the end of this file.
 */
#ifndef CGLTF_H
#define CGLTF_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <stddef.h>
#include <stdint.h>

#include <jsmn.h>

#define CGLTF_EXTENSION_FLAG_TEXTURE_TRANSFORM      (1 << 0)
#define CGLTF_EXTENSION_FLAG_MATERIALS_UNLIT        (1 << 1)
#define CGLTF_EXTENSION_FLAG_SPECULAR_GLOSSINESS    (1 << 2)
#define CGLTF_EXTENSION_FLAG_LIGHTS_PUNCTUAL        (1 << 3)
#define CGLTF_EXTENSION_FLAG_DRACO_MESH_COMPRESSION (1 << 4)
#define CGLTF_EXTENSION_FLAG_MATERIALS_CLEARCOAT    (1 << 5)
#define CGLTF_EXTENSION_FLAG_MATERIALS_IOR          (1 << 6)
#define CGLTF_EXTENSION_FLAG_MATERIALS_SPECULAR     (1 << 7)
#define CGLTF_EXTENSION_FLAG_MATERIALS_TRANSMISSION (1 << 8)
#define CGLTF_EXTENSION_FLAG_MATERIALS_SHEEN        (1 << 9)
#define CGLTF_EXTENSION_FLAG_MATERIALS_VARIANTS     (1 << 10)
#define CGLTF_EXTENSION_FLAG_MATERIALS_VOLUME       (1 << 11)
#define CGLTF_EXTENSION_FLAG_TEXTURE_BASISU        (1 << 12)

typedef size_t cgltf_size;
typedef float cgltf_float;
typedef int cgltf_int;
typedef unsigned int cgltf_uint;
typedef int cgltf_bool;

typedef enum cgltf_file_type
{
	cgltf_file_type_invalid,
	cgltf_file_type_gltf,
	cgltf_file_type_glb,
} cgltf_file_type;

typedef enum cgltf_result
{
	cgltf_result_success,
	cgltf_result_data_too_short,
	cgltf_result_unknown_format,
	cgltf_result_invalid_json,
	cgltf_result_invalid_gltf,
	cgltf_result_invalid_options,
	cgltf_result_file_not_found,
	cgltf_result_io_error,
	cgltf_result_out_of_memory,
	cgltf_result_legacy_gltf,
} cgltf_result;

typedef struct cgltf_memory_options
{
	void* (*alloc)(void* user, cgltf_size size);
	void (*free) (void* user, void* ptr);
	void* user_data;
} cgltf_memory_options;

typedef struct cgltf_file_options
{
	cgltf_result(*read)(const struct cgltf_memory_options* memory_options, const struct cgltf_file_options* file_options, const char* path, cgltf_size* size, void** data);
	void (*release)(const struct cgltf_memory_options* memory_options, const struct cgltf_file_options* file_options, void* data);
	void* user_data;
} cgltf_file_options;

typedef struct cgltf_options
{
	cgltf_file_type type; /* invalid == auto detect */
	cgltf_size json_token_count; /* 0 == auto */
	cgltf_memory_options memory;
	cgltf_file_options file;
} cgltf_options;

typedef enum cgltf_buffer_view_type
{
	cgltf_buffer_view_type_invalid,
	cgltf_buffer_view_type_indices,
	cgltf_buffer_view_type_vertices,
} cgltf_buffer_view_type;

typedef enum cgltf_attribute_type
{
	cgltf_attribute_type_invalid,
	cgltf_attribute_type_position,
	cgltf_attribute_type_normal,
	cgltf_attribute_type_tangent,
	cgltf_attribute_type_texcoord,
	cgltf_attribute_type_color,
	cgltf_attribute_type_joints,
	cgltf_attribute_type_weights,
} cgltf_attribute_type;

typedef enum cgltf_component_type
{
	cgltf_component_type_invalid,
	cgltf_component_type_r_8, /* BYTE */
	cgltf_component_type_r_8u, /* UNSIGNED_BYTE */
	cgltf_component_type_r_16, /* SHORT */
	cgltf_component_type_r_16u, /* UNSIGNED_SHORT */
	cgltf_component_type_r_32u, /* UNSIGNED_INT */
	cgltf_component_type_r_32f, /* FLOAT */
} cgltf_component_type;

typedef enum cgltf_type
{
	cgltf_type_invalid,
	cgltf_type_scalar,
	cgltf_type_vec2,
	cgltf_type_vec3,
	cgltf_type_vec4,
	cgltf_type_mat2,
	cgltf_type_mat3,
	cgltf_type_mat4,
} cgltf_type;

typedef enum cgltf_primitive_type
{
	cgltf_primitive_type_points,
	cgltf_primitive_type_lines,
	cgltf_primitive_type_line_loop,
	cgltf_primitive_type_line_strip,
	cgltf_primitive_type_triangles,
	cgltf_primitive_type_triangle_strip,
	cgltf_primitive_type_triangle_fan,
} cgltf_primitive_type;

typedef enum cgltf_alpha_mode
{
	cgltf_alpha_mode_opaque,
	cgltf_alpha_mode_mask,
	cgltf_alpha_mode_blend,
} cgltf_alpha_mode;

typedef enum cgltf_animation_path_type {
	cgltf_animation_path_type_invalid,
	cgltf_animation_path_type_translation,
	cgltf_animation_path_type_rotation,
	cgltf_animation_path_type_scale,
	cgltf_animation_path_type_weights,
} cgltf_animation_path_type;

typedef enum cgltf_interpolation_type {
	cgltf_interpolation_type_linear,
	cgltf_interpolation_type_step,
	cgltf_interpolation_type_cubic_spline,
} cgltf_interpolation_type;

typedef enum cgltf_camera_type {
	cgltf_camera_type_invalid,
	cgltf_camera_type_perspective,
	cgltf_camera_type_orthographic,
} cgltf_camera_type;

typedef enum cgltf_light_type {
	cgltf_light_type_invalid,
	cgltf_light_type_directional,
	cgltf_light_type_point,
	cgltf_light_type_spot,
} cgltf_light_type;

typedef struct cgltf_extras {
	cgltf_size start_offset;
	cgltf_size end_offset;
} cgltf_extras;

typedef struct cgltf_extension {
	char* name;
	char* data;
} cgltf_extension;

typedef struct cgltf_buffer
{
	char* name;
	cgltf_size size;
	char* uri;
	void* data; /* loaded by cgltf_load_buffers */
	cgltf_extras extras;
	cgltf_size extensions_count;
	cgltf_extension* extensions;
} cgltf_buffer;

typedef enum cgltf_meshopt_compression_mode {
	cgltf_meshopt_compression_mode_invalid,
	cgltf_meshopt_compression_mode_attributes,
	cgltf_meshopt_compression_mode_triangles,
	cgltf_meshopt_compression_mode_indices,
} cgltf_meshopt_compression_mode;

typedef enum cgltf_meshopt_compression_filter {
	cgltf_meshopt_compression_filter_none,
	cgltf_meshopt_compression_filter_octahedral,
	cgltf_meshopt_compression_filter_quaternion,
	cgltf_meshopt_compression_filter_exponential,
} cgltf_meshopt_compression_filter;

typedef struct cgltf_meshopt_compression
{
	cgltf_buffer* buffer;
	cgltf_size offset;
	cgltf_size size;
	cgltf_size stride;
	cgltf_size count;
	cgltf_meshopt_compression_mode mode;
	cgltf_meshopt_compression_filter filter;
} cgltf_meshopt_compression;

typedef struct cgltf_buffer_view
{
	char *name;
	cgltf_buffer* buffer;
	cgltf_size offset;
	cgltf_size size;
	cgltf_size stride; /* 0 == automatically determined by accessor */
	cgltf_buffer_view_type type;
	void* data; /* overrides buffer->data if present, filled by extensions */
	cgltf_bool has_meshopt_compression;
	cgltf_meshopt_compression meshopt_compression;
	cgltf_extras extras;
	cgltf_size extensions_count;
	cgltf_extension* extensions;
} cgltf_buffer_view;

typedef struct cgltf_accessor_sparse
{
	cgltf_size count;
	cgltf_buffer_view* indices_buffer_view;
	cgltf_size indices_byte_offset;
	cgltf_component_type indices_component_type;
	cgltf_buffer_view* values_buffer_view;
	cgltf_size values_byte_offset;
	cgltf_extras extras;
	cgltf_extras indices_extras;
	cgltf_extras values_extras;
	cgltf_size extensions_count;
	cgltf_extension* extensions;
	cgltf_size indices_extensions_count;
	cgltf_extension* indices_extensions;
	cgltf_size values_extensions_count;
	cgltf_extension* values_extensions;
} cgltf_accessor_sparse;

typedef struct cgltf_accessor
{
	char* name;
	cgltf_component_type component_type;
	cgltf_bool normalized;
	cgltf_type type;
	cgltf_size offset;
	cgltf_size count;
	cgltf_size stride;
	cgltf_buffer_view* buffer_view;
	cgltf_bool has_min;
	cgltf_float min[16];
	cgltf_bool has_max;
	cgltf_float max[16];
	cgltf_bool is_sparse;
	cgltf_accessor_sparse sparse;
	cgltf_extras extras;
	cgltf_size extensions_count;
	cgltf_extension* extensions;
} cgltf_accessor;

typedef struct cgltf_attribute
{
	char* name;
	cgltf_attribute_type type;
	cgltf_int index;
	cgltf_accessor* data;
} cgltf_attribute;

typedef struct cgltf_image
{
	char* name;
	char* uri;
	cgltf_buffer_view* buffer_view;
	char* mime_type;
	cgltf_extras extras;
	cgltf_size extensions_count;
	cgltf_extension* extensions;
} cgltf_image;

typedef struct cgltf_sampler
{
	char* name;
	cgltf_int mag_filter;
	cgltf_int min_filter;
	cgltf_int wrap_s;
	cgltf_int wrap_t;
	cgltf_extras extras;
	cgltf_size extensions_count;
	cgltf_extension* extensions;
} cgltf_sampler;

typedef struct cgltf_texture
{
	char* name;
	cgltf_image* image;
	cgltf_sampler* sampler;
	cgltf_bool has_basisu;
	cgltf_image* basisu_image;
	cgltf_extras extras;
	cgltf_size extensions_count;
	cgltf_extension* extensions;
} cgltf_texture;

typedef struct cgltf_texture_transform
{
	cgltf_float offset[2];
	cgltf_float rotation;
	cgltf_float scale[2];
	cgltf_int texcoord;
} cgltf_texture_transform;

typedef struct cgltf_texture_view
{
	cgltf_texture* texture;
	cgltf_int texcoord;
	cgltf_float scale; /* equivalent to strength for occlusion_texture */
	cgltf_bool has_transform;
	cgltf_texture_transform transform;
	cgltf_extras extras;
	cgltf_size extensions_count;
	cgltf_extension* extensions;
} cgltf_texture_view;

typedef struct cgltf_pbr_metallic_roughness
{
	cgltf_texture_view base_color_texture;
	cgltf_texture_view metallic_roughness_texture;

	cgltf_float base_color_factor[4];
	cgltf_float metallic_factor;
	cgltf_float roughness_factor;

	cgltf_extras extras;
} cgltf_pbr_metallic_roughness;

typedef struct cgltf_pbr_specular_glossiness
{
	cgltf_texture_view diffuse_texture;
	cgltf_texture_view specular_glossiness_texture;

	cgltf_float diffuse_factor[4];
	cgltf_float specular_factor[3];
	cgltf_float glossiness_factor;
} cgltf_pbr_specular_glossiness;

typedef struct cgltf_clearcoat
{
	cgltf_texture_view clearcoat_texture;
	cgltf_texture_view clearcoat_roughness_texture;
	cgltf_texture_view clearcoat_normal_texture;

	cgltf_float clearcoat_factor;
	cgltf_float clearcoat_roughness_factor;
} cgltf_clearcoat;

typedef struct cgltf_transmission
{
	cgltf_texture_view transmission_texture;
	cgltf_float transmission_factor;
} cgltf_transmission;

typedef struct cgltf_ior
{
	cgltf_float ior;
} cgltf_ior;

typedef struct cgltf_specular
{
	cgltf_texture_view specular_texture;
	cgltf_texture_view specular_color_texture;
	cgltf_float specular_color_factor[3];
	cgltf_float specular_factor;
} cgltf_specular;

typedef struct cgltf_volume
{
	cgltf_texture_view thickness_texture;
	cgltf_float thickness_factor;
	cgltf_float attenuation_color[3];
	cgltf_float attenuation_distance;
} cgltf_volume;

typedef struct cgltf_sheen
{
	cgltf_texture_view sheen_color_texture;
	cgltf_float sheen_color_factor[3];
	cgltf_texture_view sheen_roughness_texture;
	cgltf_float sheen_roughness_factor;
} cgltf_sheen;

typedef struct cgltf_material
{
	char* name;
	cgltf_bool has_pbr_metallic_roughness;
	cgltf_bool has_pbr_specular_glossiness;
	cgltf_bool has_clearcoat;
	cgltf_bool has_transmission;
	cgltf_bool has_volume;
	cgltf_bool has_ior;
	cgltf_bool has_specular;
	cgltf_bool has_sheen;
	cgltf_pbr_metallic_roughness pbr_metallic_roughness;
	cgltf_pbr_specular_glossiness pbr_specular_glossiness;
	cgltf_clearcoat clearcoat;
	cgltf_ior ior;
	cgltf_specular specular;
	cgltf_sheen sheen;
	cgltf_transmission transmission;
	cgltf_volume volume;
	cgltf_texture_view normal_texture;
	cgltf_texture_view occlusion_texture;
	cgltf_texture_view emissive_texture;
	cgltf_float emissive_factor[3];
	cgltf_alpha_mode alpha_mode;
	cgltf_float alpha_cutoff;
	cgltf_bool double_sided;
	cgltf_bool unlit;
	cgltf_extras extras;
	cgltf_size extensions_count;
	cgltf_extension* extensions;
} cgltf_material;

typedef struct cgltf_material_mapping
{
	cgltf_size variant;
	cgltf_material* material;
	cgltf_extras extras;
} cgltf_material_mapping;

typedef struct cgltf_morph_target {
	cgltf_attribute* attributes;
	cgltf_size attributes_count;
} cgltf_morph_target;

typedef struct cgltf_draco_mesh_compression {
	cgltf_buffer_view* buffer_view;
	cgltf_attribute* attributes;
	cgltf_size attributes_count;
} cgltf_draco_mesh_compression;

typedef struct cgltf_primitive {
	cgltf_primitive_type type;
	cgltf_accessor* indices;
	cgltf_material* material;
	cgltf_attribute* attributes;
	cgltf_size attributes_count;
	cgltf_morph_target* targets;
	cgltf_size targets_count;
	cgltf_extras extras;
	cgltf_bool has_draco_mesh_compression;
	cgltf_draco_mesh_compression draco_mesh_compression;
	cgltf_material_mapping* mappings;
	cgltf_size mappings_count;
	cgltf_size extensions_count;
	cgltf_extension* extensions;
} cgltf_primitive;

typedef struct cgltf_mesh {
	char* name;
	cgltf_primitive* primitives;
	cgltf_size primitives_count;
	cgltf_float* weights;
	cgltf_size weights_count;
	char** target_names;
	cgltf_size target_names_count;
	cgltf_extras extras;
	cgltf_size extensions_count;
	cgltf_extension* extensions;
} cgltf_mesh;

typedef struct cgltf_node cgltf_node;

typedef struct cgltf_skin {
	char* name;
	cgltf_node** joints;
	cgltf_size joints_count;
	cgltf_node* skeleton;
	cgltf_accessor* inverse_bind_matrices;
	cgltf_extras extras;
	cgltf_size extensions_count;
	cgltf_extension* extensions;
} cgltf_skin;

typedef struct cgltf_camera_perspective {
	cgltf_bool has_aspect_ratio;
	cgltf_float aspect_ratio;
	cgltf_float yfov;
	cgltf_bool has_zfar;
	cgltf_float zfar;
	cgltf_float znear;
	cgltf_extras extras;
} cgltf_camera_perspective;

typedef struct cgltf_camera_orthographic {
	cgltf_float xmag;
	cgltf_float ymag;
	cgltf_float zfar;
	cgltf_float znear;
	cgltf_extras extras;
} cgltf_camera_orthographic;

typedef struct cgltf_camera {
	char* name;
	cgltf_camera_type type;
	union {
		cgltf_camera_perspective perspective;
		cgltf_camera_orthographic orthographic;
	} data;
	cgltf_extras extras;
	cgltf_size extensions_count;
	cgltf_extension* extensions;
} cgltf_camera;

typedef struct cgltf_light {
	char* name;
	cgltf_float color[3];
	cgltf_float intensity;
	cgltf_light_type type;
	cgltf_float range;
	cgltf_float spot_inner_cone_angle;
	cgltf_float spot_outer_cone_angle;
} cgltf_light;

struct cgltf_node {
	char* name;
	cgltf_node* parent;
	cgltf_node** children;
	cgltf_size children_count;
	cgltf_skin* skin;
	cgltf_mesh* mesh;
	cgltf_camera* camera;
	cgltf_light* light;
	cgltf_float* weights;
	cgltf_size weights_count;
	cgltf_bool has_translation;
	cgltf_bool has_rotation;
	cgltf_bool has_scale;
	cgltf_bool has_matrix;
	cgltf_float translation[3];
	cgltf_float rotation[4];
	cgltf_float scale[3];
	cgltf_float matrix[16];
	cgltf_extras extras;
	cgltf_size extensions_count;
	cgltf_extension* extensions;
};

typedef struct cgltf_scene {
	char* name;
	cgltf_node** nodes;
	cgltf_size nodes_count;
	cgltf_extras extras;
	cgltf_size extensions_count;
	cgltf_extension* extensions;
} cgltf_scene;

typedef struct cgltf_animation_sampler {
	cgltf_accessor* input;
	cgltf_accessor* output;
	cgltf_interpolation_type interpolation;
	cgltf_extras extras;
	cgltf_size extensions_count;
	cgltf_extension* extensions;
} cgltf_animation_sampler;

typedef struct cgltf_animation_channel {
	cgltf_animation_sampler* sampler;
	cgltf_node* target_node;
	cgltf_animation_path_type target_path;
	cgltf_extras extras;
	cgltf_size extensions_count;
	cgltf_extension* extensions;
} cgltf_animation_channel;

typedef struct cgltf_animation {
	char* name;
	cgltf_animation_sampler* samplers;
	cgltf_size samplers_count;
	cgltf_animation_channel* channels;
	cgltf_size channels_count;
	cgltf_extras extras;
	cgltf_size extensions_count;
	cgltf_extension* extensions;
} cgltf_animation;

typedef struct cgltf_material_variant
{
	char* name;
	cgltf_extras extras;
} cgltf_material_variant;

typedef struct cgltf_asset {
	char* copyright;
	char* generator;
	char* version;
	char* min_version;
	cgltf_extras extras;
	cgltf_size extensions_count;
	cgltf_extension* extensions;
} cgltf_asset;

typedef struct cgltf_data
{
	cgltf_file_type file_type;
	void* file_data;

	cgltf_asset asset;

	cgltf_mesh* meshes;
	cgltf_size meshes_count;

	cgltf_material* materials;
	cgltf_size materials_count;

	cgltf_accessor* accessors;
	cgltf_size accessors_count;

	cgltf_buffer_view* buffer_views;
	cgltf_size buffer_views_count;

	cgltf_buffer* buffers;
	cgltf_size buffers_count;

	cgltf_image* images;
	cgltf_size images_count;

	cgltf_texture* textures;
	cgltf_size textures_count;

	cgltf_sampler* samplers;
	cgltf_size samplers_count;

	cgltf_skin* skins;
	cgltf_size skins_count;

	cgltf_camera* cameras;
	cgltf_size cameras_count;

	cgltf_light* lights;
	cgltf_size lights_count;

	cgltf_node* nodes;
	cgltf_size nodes_count;

	cgltf_scene* scenes;
	cgltf_size scenes_count;

	cgltf_scene* scene;

	cgltf_animation* animations;
	cgltf_size animations_count;

	cgltf_material_variant* variants;
	cgltf_size variants_count;

	cgltf_extras extras;

	cgltf_size data_extensions_count;
	cgltf_extension* data_extensions;

	char** extensions_used;
	cgltf_size extensions_used_count;

	char** extensions_required;
	cgltf_size extensions_required_count;

	const char* json;
	cgltf_size json_size;

	const void* bin;
	cgltf_size bin_size;

	cgltf_memory_options memory;
	cgltf_file_options file;
} cgltf_data;

typedef struct {
	char* buffer;
	cgltf_size buffer_size;
	cgltf_size remaining;
	char* cursor;
	cgltf_size tmp;
	cgltf_size chars_written;
	const cgltf_data* data;
	int depth;
	const char* indent;
	int needs_comma;
	uint32_t extension_flags;
	uint32_t required_extension_flags;
} cgltf_write_context;

extern cgltf_result cgltf_parse_json(cgltf_options* options, const uint8_t* json_chunk, cgltf_size size, cgltf_data** out_data);

extern cgltf_size cgltf_calc_size(cgltf_type type, cgltf_component_type component_type);

extern cgltf_size cgltf_component_size(cgltf_component_type component_type);

extern int cgltf_fixup_pointers(cgltf_data* out_data);

extern cgltf_result cgltf_parse(
		const cgltf_options* options,
		const void* data,
		cgltf_size size,
		cgltf_data** out_data);

extern cgltf_result cgltf_parse_file(
		const cgltf_options* options,
		const char* path,
		cgltf_data** out_data);

extern cgltf_result cgltf_load_buffers(
		const cgltf_options* options,
		cgltf_data* data,
		const char* gltf_path);

extern cgltf_result cgltf_load_buffer_base64(const cgltf_options* options, cgltf_size size, const char* base64, void** out_data);

extern void cgltf_decode_uri(char* uri);

extern cgltf_result cgltf_validate(cgltf_data* data);

extern void cgltf_free(cgltf_data* data);

extern void cgltf_node_transform_local(const cgltf_node* node, cgltf_float* out_matrix);
extern void cgltf_node_transform_world(const cgltf_node* node, cgltf_float* out_matrix);

extern cgltf_bool cgltf_accessor_read_float(const cgltf_accessor* accessor, cgltf_size index, cgltf_float* out, cgltf_size element_size);
extern cgltf_bool cgltf_accessor_read_uint(const cgltf_accessor* accessor, cgltf_size index, cgltf_uint* out, cgltf_size element_size);
extern cgltf_size cgltf_accessor_read_index(const cgltf_accessor* accessor, cgltf_size index);

extern cgltf_size cgltf_num_components(cgltf_type type);

extern cgltf_size cgltf_accessor_unpack_floats(const cgltf_accessor* accessor, cgltf_float* out, cgltf_size float_count);

extern cgltf_result cgltf_copy_extras_json(const cgltf_data* data, const cgltf_extras* extras, char* dest, cgltf_size* dest_size);

extern cgltf_result cgltf_write_file(const cgltf_options* options, const char* path, const cgltf_data* data);
extern cgltf_size cgltf_write(const cgltf_options* options, char* buffer, cgltf_size size, const cgltf_data* data);

#if CGLTF_VALIDATE_ENABLE_ASSERTS
#define CGLTF_ASSERT_IF(cond, result) assert(!(cond)); if (cond) return result;
#else
#define CGLTF_ASSERT_IF(cond, result) if (cond) return result;
#endif

#define CGLTF_ERROR_JSON -1
#define CGLTF_ERROR_NOMEM -2
#define CGLTF_ERROR_LEGACY -3

#define CGLTF_CHECK_TOKTYPE(tok_, type_) if ((tok_).type != (type_)) { return CGLTF_ERROR_JSON; }
#define CGLTF_CHECK_KEY(tok_) if ((tok_).type != JSMN_STRING || (tok_).size == 0) { return CGLTF_ERROR_JSON; } /* checking size for 0 verifies that a value follows the key */

#define CGLTF_PTRINDEX(type, idx) (type*)((cgltf_size)idx + 1)
#define CGLTF_PTRFIXUP(var, data, size) if (var) { if ((cgltf_size)var > size) { return CGLTF_ERROR_JSON; } var = &data[(cgltf_size)var-1]; }
#define CGLTF_PTRFIXUP_REQ(var, data, size) if (!var || (cgltf_size)var > size) { return CGLTF_ERROR_JSON; } var = &data[(cgltf_size)var-1];

#ifndef CGLTF_MALLOC
#define CGLTF_MALLOC(size) malloc(size)
#endif
#ifndef CGLTF_FREE
#define CGLTF_FREE(ptr) free(ptr)
#endif
#ifndef CGLTF_ATOI
#define CGLTF_ATOI(str) atoi(str)
#endif
#ifndef CGLTF_ATOF
#define CGLTF_ATOF(str) atof(str)
#endif
#ifndef CGLTF_VALIDATE_ENABLE_ASSERTS
#define CGLTF_VALIDATE_ENABLE_ASSERTS 0
#endif

#define CGLTF_MIN(a, b) (a < b ? a : b)

#ifdef FLT_DECIMAL_DIG
	// FLT_DECIMAL_DIG is C11
	#define CGLTF_DECIMAL_DIG (FLT_DECIMAL_DIG)
#else
	#define CGLTF_DECIMAL_DIG 9
#endif

#define CGLTF_SPRINTF(...) { \
		context->tmp = snprintf ( context->cursor, context->remaining, __VA_ARGS__ ); \
		context->chars_written += context->tmp; \
		if (context->cursor) { \
			context->cursor += context->tmp; \
			context->remaining -= context->tmp; \
		} }

#define CGLTF_SNPRINTF(length, ...) { \
		context->tmp = snprintf ( context->cursor, CGLTF_MIN(length + 1, context->remaining), __VA_ARGS__ ); \
		context->chars_written += length; \
		if (context->cursor) { \
			context->cursor += length; \
			context->remaining -= length; \
		} }

#define CGLTF_WRITE_IDXPROP(label, val, start) if (val) { \
		cgltf_write_indent(context); \
		CGLTF_SPRINTF("\"%s\": %d", label, (int) (val - start)); \
		context->needs_comma = 1; }

#define CGLTF_WRITE_IDXARRPROP(label, dim, vals, start) if (vals) { \
		cgltf_write_indent(context); \
		CGLTF_SPRINTF("\"%s\": [", label); \
		for (int i = 0; i < (int)(dim); ++i) { \
			int idx = (int) (vals[i] - start); \
			if (i != 0) CGLTF_SPRINTF(","); \
			CGLTF_SPRINTF(" %d", idx); \
		} \
		CGLTF_SPRINTF(" ]"); \
		context->needs_comma = 1; }

#define CGLTF_WRITE_TEXTURE_INFO(label, info) if (info.texture) { \
		cgltf_write_line(context, "\"" label "\": {"); \
		CGLTF_WRITE_IDXPROP("index", info.texture, context->data->textures); \
		cgltf_write_intprop(context, "texCoord", info.texcoord, 0); \
		cgltf_write_floatprop(context, "scale", info.scale, 1.0f); \
		if (info.has_transform) { \
			context->extension_flags |= CGLTF_EXTENSION_FLAG_TEXTURE_TRANSFORM; \
			cgltf_write_texture_transform(context, &info.transform); \
		} \
		cgltf_write_extras(context, &info.extras); \
		cgltf_write_line(context, "}"); }

#ifdef __cplusplus
};
#endif /* __cplusplus */

#endif /* CGLTF_H */
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
