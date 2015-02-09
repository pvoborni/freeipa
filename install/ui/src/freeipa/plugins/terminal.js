/*  Authors:
 *    Petr Vobornik <pvoborni@redhat.com>
 *
 * Copyright (C) 2013 Red Hat
 * see file 'COPYING' for use and warranty information
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

define(['dojo/_base/declare',
        'dojo/_base/lang',
        'dojo/on',
        '../facets/Facet',
        '../auth',
        '../field',
        '../phases',
        '../reg',
        '../widget',
        '../widgets/Terminal'
       ],
       function(declare, lang, on, Facet, auth, field, phases, reg, widget, Terminal) {

    /**
     * Cockpit terminal plugin
     *
     *
     * @class plugins.terminal
     * @singleton
     */
    var terminal = {};


    phases.on('registration', function() {

        var w = reg.widget;
        var f = reg.field;
        w.register('terminal', Terminal);
        f.register('terminal', field.field);

    });

    return terminal;
});