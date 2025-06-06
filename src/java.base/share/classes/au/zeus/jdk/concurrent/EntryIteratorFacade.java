/* Copyright (c) 2010-2012 Zeus Project Services Pty Ltd.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package au.zeus.jdk.concurrent;

import java.util.Iterator;

/**
 *
 * @author Peter Firmstone.
 */
class EntryIteratorFacade<O, R> implements Iterator<O> {
    private Iterator<R> iterator;
    private ReferenceQueuingFactory<O, R> wf;

    EntryIteratorFacade(Iterator<R> iterator, ReferenceQueuingFactory<O, R> wf) {
        this.iterator = iterator;
        this.wf = wf;
    }

    public boolean hasNext() {
        return iterator.hasNext();
    }

    public O next() {
        return wf.pseudoReferent(iterator.next());
    }

    public void remove() {
        iterator.remove();
    }
    
}
