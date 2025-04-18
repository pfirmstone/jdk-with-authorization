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

/**
 * An interface for processing ReferenceQueue's and encapsulating Objects
 * in references and for making references appear as their referent.
 * 
 * @author Peter Firmstone
 */
interface ReferenceQueuingFactory<O, R> {

    O pseudoReferent(R u);

    R referenced(O w, boolean enque, boolean temporary);

    /**
     * This method was originally intended to process the reference queue 
     * prior to access, however this severely hurts scalability.  Now
     * reference queue's are processed with a background garbage collection
     * thread.
     * 
     * @deprecated 
     */
    @Deprecated
    void processQueue();
     
}
