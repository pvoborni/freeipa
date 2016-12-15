//
// Copyright (C) 2015  FreeIPA Contributors see COPYING for license
//

define(['dojo/_base/declare',
        'dojo/_base/lang',
        'dojo/on',
        'dojo/dom-construct',
        'dojo/dom-class',
        './HeaderMixin',
        '../builder',
        '../facet',
        '../ipa',
        '../text',
        '../widgets/ActionDropdownWidget'
       ],
       function(declare, lang, on, construct, dom_class, HeaderMixin,
            builder, mod_facet, IPA, text, ActionDropdownWidget) {


/**
 * Extended Header Mixin
 *
 * Extension of header - header with title and facet groups. Requires
 * facets.ActionMixin.
 *
 * @class facets.ExtendedHeaderMixin
 */
var ExtendedHeaderMixin = declare([HeaderMixin], {
    // definiton of order of called methods in inheritance

    /**
     * Facet header
     * @property {facet.facet_header}
     */
    header: null,

    /** Constructor */
    constructor: function(spec) {

        this.header = builder.build(
            '',
            spec.header || { init_group_names: true},
            {},
            {
                $pre_ops: [{ facet: this }],
                $factory: mod_facet.facet_header
            }
        );
        this.header.init();
    }
});

return ExtendedHeaderMixin;
});
