/*  -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 4; tab-width: 4 -*-  */
/*  Please make sure that the TAB width in your editor is set to 4 spaces  */

/*\
|*|
|*| nautilus-checksums.c
|*|
|*| https://gitlab.gnome.org/madmurphy/nautilus-checksums
|*|
|*| Copyright (C) 2022 <madmurphy333@gmail.com>
|*|
|*| **Nautilus Checksums** is free software: you can redistribute it and/or
|*| modify it under the terms of the GNU General Public License as published by
|*| the Free Software Foundation, either version 3 of the License, or (at your
|*| option) any later version.
|*|
|*| **Nautilus Checksums** is distributed in the hope that it will be useful,
|*| but WITHOUT ANY WARRANTY; without even the implied warranty of
|*| MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
|*| Public License for more details.
|*|
|*| You should have received a copy of the GNU General Public License along
|*| with this program. If not, see <http://www.gnu.org/licenses/>.
|*|
\*/



#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdbool.h>
#include <stdio.h>
#include <stdatomic.h>
#include <glib.h>
#include <nautilus-extension.h>



/*\
|*|
|*| BUILD SETTINGS
|*|
\*/


#ifdef ENABLE_NLS
#include <glib/gi18n-lib.h>
#define I18N_INIT() \
	bindtextdomain(GETTEXT_PACKAGE, PACKAGE_LOCALE_DIR)
#else
#define _(STRING) ((char *) (STRING))
#define g_dngettext(DOMAIN, STRING1, STRING2, NUM) \
	((NUM) > 1 ? (char *) (STRING2) : (char *) (STRING1))
#define I18N_INIT()
#endif



/*\
|*|
|*| GLOBAL TYPES AND VARIABLES
|*|
\*/


typedef struct NautilusChecksums {
	GObject parent_slot;
} NautilusChecksums;


typedef struct NautilusChecksumsClass {
	GObjectClass parent_slot;
} NautilusChecksumsClass;


typedef struct NautilusChecksumsGoal {
	NautilusFileInfo * const file_info;
	GFileInputStream * const stream;
	GListStore * const chsum_group;
	atomic_size_t refcount;
} NautilusChecksumsGoal;


typedef struct NautilusChecksumsResults {
	GListStore * const chsum_group;
	GChecksum
		* const md5sum,
		* const sha1sum,
		* const sha256sum,
		* const sha512sum,
		* const sha384sum;
} NautilusChecksumsResults;


static GType provider_types[1];
static GType nautilus_checksums_type;
static GObjectClass * parent_class;
static GThreadPool * chsum_calculators;



/*\
|*|
|*| FUNCTIONS
|*|
\*/


static void on_properties_model_dispose (
	const gpointer v_goal,
	GObject * const properties_model G_GNUC_UNUSED
) {

	#define goal ((NautilusChecksumsGoal *) v_goal)

	if (atomic_fetch_sub(&goal->refcount, 1) == 1) {

		g_free(v_goal);

	}

	#undef goal

}


static gboolean nautilus_checksums_push_results_idle (
	gpointer const v_results
) {

	#define results ((NautilusChecksumsResults *) v_results)

	g_list_store_append(
		results->chsum_group,
		nautilus_properties_item_new(
			"MD5",
			g_checksum_get_string(results->md5sum)
		)
	);

	g_list_store_append(
		results->chsum_group,
		nautilus_properties_item_new(
			"SHA1",
			g_checksum_get_string(results->sha1sum)
		)
	);

	g_list_store_append(
		results->chsum_group,
		nautilus_properties_item_new(
			"SHA256",
			g_checksum_get_string(results->sha256sum)
		)
	);

	g_list_store_append(
		results->chsum_group,
		nautilus_properties_item_new(
			"SHA512",
			g_checksum_get_string(results->sha512sum)
		)
	);

	g_list_store_append(
		results->chsum_group,
		nautilus_properties_item_new(
			"SHA384",
			g_checksum_get_string(results->sha384sum)
		)
	);

	g_checksum_free(results->md5sum);
	g_checksum_free(results->sha1sum);
	g_checksum_free(results->sha256sum);
	g_checksum_free(results->sha512sum);
	g_checksum_free(results->sha384sum);
	g_object_unref(results->chsum_group);
	g_free(v_results);
	return false;

	#undef results

}


static void nautilus_checksums_thread (
	const gpointer v_goal,
	const gpointer pool_data G_GNUC_UNUSED
) {

	#define goal ((NautilusChecksumsGoal *) v_goal)

	GFileInputStream * const stream = goal->stream;
	NautilusFileInfo * const file_info = goal->file_info;
	GError * readerr = NULL;
	gchar * uri;

	if (atomic_load(&goal->refcount) < 2) {

		g_object_unref(goal->chsum_group);
		g_free(v_goal);
		goto close_and_exit;

	}

	const NautilusChecksumsResults results = {
		.chsum_group = goal->chsum_group,
		.md5sum = g_checksum_new(G_CHECKSUM_MD5),
		.sha1sum = g_checksum_new(G_CHECKSUM_SHA1),
		.sha256sum = g_checksum_new(G_CHECKSUM_SHA256),
		.sha512sum = g_checksum_new(G_CHECKSUM_SHA512),
		.sha384sum = g_checksum_new(G_CHECKSUM_SHA384)
	};

	if (
		!results.md5sum ||
		!results.sha1sum ||
		!results.sha256sum ||
		!results.sha512sum ||
		!results.sha384sum
	) {

		g_warning(
			_(
				"Could not allocate memory for calculating one or more "
				"checksums"
			)
		);

		goto checksum_error;

	}

	guchar * const buf = g_malloc(BUFSIZ);
	gssize size_read;
	bool b_continue;


	/* \                                /\
	\ */     get_file_chunk:           /* \
	 \/     ______________________     \ */


	if (
		(size_read = g_input_stream_read(
			G_INPUT_STREAM(stream),
			buf,
			BUFSIZ,
			NULL,
			&readerr
		)) > 0
	) {

		g_checksum_update(results.md5sum, buf, size_read);
		g_checksum_update(results.sha256sum, buf, size_read);
		g_checksum_update(results.sha1sum, buf, size_read);
		g_checksum_update(results.sha512sum, buf, size_read);
		g_checksum_update(results.sha384sum, buf, size_read);
		b_continue = atomic_load(&goal->refcount) > 1;

		if (b_continue) {

			goto get_file_chunk;

		}

	}

	g_free(buf);

	switch (readerr ? 2 : !b_continue) {

		case 0:

			g_idle_add(
				nautilus_checksums_push_results_idle,
				g_memdup2(&results, sizeof(NautilusChecksumsResults))
			);

			break;

		case 2:

			uri = nautilus_file_info_get_uri(file_info);
			g_warning("%s (%s) // %s", _("I/O error"), uri, readerr->message);
			g_free(uri);
			g_clear_error(&readerr);

		/*  fallthrough  */
		case 1:
		checksum_error:

			g_checksum_free(results.md5sum);
			g_checksum_free(results.sha1sum);
			g_checksum_free(results.sha256sum);
			g_checksum_free(results.sha512sum);
			g_checksum_free(results.sha384sum);
			g_object_unref(results.chsum_group);

	}

	if (atomic_fetch_sub(&goal->refcount, 1) == 1) {

		g_free(v_goal);

	}

	#undef goal


	/* \                                /\
	\ */     close_and_exit:           /* \
	 \/     ______________________     \ */


	if (!g_input_stream_close(G_INPUT_STREAM(stream), NULL, &readerr)) {

		uri = nautilus_file_info_get_uri(file_info);

		g_warning(
			"%s (%s) // %s",
			_("Unable to close file stream"),
			uri,
			readerr->message
		);

		g_free(uri);
		g_error_free(readerr);

	}

}


static GList * nautilus_checksums_get_models (
	NautilusPropertiesModelProvider * const provider G_GNUC_UNUSED,
	GList * const files
) {

	if (
		!files ||
		files->next ||
		nautilus_file_info_is_directory(NAUTILUS_FILE_INFO(files->data))
	) {

		return NULL;

	}

	gpointer __ptr_placeholder__;

	#define location __ptr_placeholder__

	location = nautilus_file_info_get_location(files->data);

	NautilusChecksumsGoal goal_source = {
		.file_info = files->data,
		.stream = g_file_read(location, NULL, NULL),
		.chsum_group = NULL,
		.refcount = 2
	};

	g_object_unref(location);

	#undef location

	if (!goal_source.stream) {

		return NULL;

	}

	#define goal __ptr_placeholder__

	GError * err = NULL;

	*((GListStore **) &goal_source.chsum_group) =
		g_list_store_new(NAUTILUS_TYPE_PROPERTIES_ITEM);

	goal = g_memdup2(&goal_source, sizeof(NautilusChecksumsGoal));

	if (!g_thread_pool_push(chsum_calculators, goal, &err)) {

		/*  The task will be added to the queue anyway!  */

		gchar * const uri = nautilus_file_info_get_uri(files->data);

		g_warning(
			"%s (%s) // %s",
			_("Unable to compute checksums at the moment"),
			uri,
			err->message
		);

		g_clear_error(&err);
		g_free(uri);

	}

	NautilusPropertiesModel * const properties_model =
		nautilus_properties_model_new(
			_("Checksums"),
			G_LIST_MODEL(goal_source.chsum_group)
		);

	g_object_weak_ref(
		G_OBJECT(properties_model),
		on_properties_model_dispose,
		goal
	);

	return g_list_append(NULL, properties_model);

	#undef goal

}


static void nautilus_checksums_properties_model_provider_iface_init (
	NautilusPropertiesModelProviderInterface * const iface,
	const gpointer iface_data G_GNUC_UNUSED
) {

	iface->get_models = nautilus_checksums_get_models;

}


static void nautilus_checksums_class_init (
	NautilusChecksumsClass * const nautilus_checksums_class,
	const gpointer class_data G_GNUC_UNUSED
) {

	parent_class = g_type_class_peek_parent(nautilus_checksums_class);

}


static void nautilus_checksums_register_type (
	GTypeModule * const module
) {

	static const GTypeInfo info = {
		sizeof(NautilusChecksumsClass),
		(GBaseInitFunc) NULL,
		(GBaseFinalizeFunc) NULL,
		(GClassInitFunc) nautilus_checksums_class_init,
		(GClassFinalizeFunc) NULL,
		NULL,
		sizeof(NautilusChecksums),
		0,
		(GInstanceInitFunc) NULL,
		(GTypeValueTable *) NULL
	};

	nautilus_checksums_type = g_type_module_register_type(
		module,
		G_TYPE_OBJECT,
		"NautilusChecksums",
		&info,
		0
	);

	static const GInterfaceInfo properties_model_provider_iface_info = {
		(GInterfaceInitFunc)
			nautilus_checksums_properties_model_provider_iface_init,
		(GInterfaceFinalizeFunc) NULL,
		NULL
	};

	g_type_module_add_interface(
		module,
		nautilus_checksums_type,
		NAUTILUS_TYPE_PROPERTIES_MODEL_PROVIDER,
		&properties_model_provider_iface_info
	);

}


GType nautilus_checksums_get_type (void) {

	return nautilus_checksums_type;

}


void nautilus_module_shutdown (void) {

	if (chsum_calculators) {

		g_thread_pool_free(chsum_calculators, true, true);

	}

}


void nautilus_module_list_types (
	const GType ** const types,
	int * const num_types
) {

	*types = provider_types;
	*num_types = G_N_ELEMENTS(provider_types);

}


void nautilus_module_initialize (
	GTypeModule * const module
) {

	GError * err = NULL;

	I18N_INIT();

	chsum_calculators =
		g_thread_pool_new(nautilus_checksums_thread, NULL, -1, false, &err);

	if (err) {

		g_warning(
			"%s // %s",
			_(
				"Unable to create thread pool for calculations - Nautilus "
				"Checksums will be disabled"
			),
			err->message
		);

		g_error_free(err);
		return;

	}

	nautilus_checksums_register_type(module);
	*provider_types = nautilus_checksums_get_type();

}


/*  EOF  */

