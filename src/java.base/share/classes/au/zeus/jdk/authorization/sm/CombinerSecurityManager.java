/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package au.zeus.jdk.authorization.sm;

import java.security.AccessControlContext;
import java.security.AccessControlException;
import java.security.AccessController;
import java.security.DomainCombiner;
import java.security.Guard;
import java.security.Permission;
import java.security.Policy;
import java.security.PrivilegedAction;
import java.security.ProtectionDomain;
import java.security.SecurityPermission;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.NavigableSet;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import java.util.concurrent.FutureTask;
import java.util.concurrent.RunnableFuture;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import au.zeus.jdk.authorization.policy.PolicyInitializationException;
import au.zeus.jdk.authorization.policy.PermissionComparator;
import au.zeus.jdk.authorization.policy.ConcurrentPolicyFile;
import au.zeus.jdk.concurrent.RC;
import au.zeus.jdk.concurrent.Ref;
import au.zeus.jdk.concurrent.Referrer;
import java.lang.ScopedValue.CallableOp;
import java.util.concurrent.Executors;

/**
 * CombinerSecurityManager, is intended to be a highly scalable
 * SecurityManager implementation that caches the results of security checks
 * for each context, which may be an instance of
 * AccessControlContext.  Stale records are pruned from the cache.
 * 
 * This SecurityManager should be tuned for garbage collection for a large
 * young generation heap, since many young objects are created and discarded.
 * 
 * It is recommended that this SecurityManager be installed from the command
 * line in order to load as early as possible.
 * 
 * Apart from Permission objects and java.security.Policy.getPolicy() class
 * lock (Bug ID: 7093090 fixed in jdk8(b15), this SecurityManager is non
 * blocking, including the cache it keeps to prevent repeat security checks.
 * 
 * @see AccessControlContext
 * 
 * @author Peter Firmstone
 * @since 3.0.0
 */
@SuppressWarnings("removal")
public class CombinerSecurityManager 
extends SecurityManager implements CachingSecurityManager {
    private static Logger logger;
    private static final Object loggerLock = new Object();
    private static final ScopedValue<Integer> TRUSTED_RECURSIVE_CALL = ScopedValue.newInstance();

    /**
     * Logger is lazily loaded, the SecurityManager can be loaded prior to
     * the system ClassLoader, attempting to load a Logger will cause a 
     * NullPointerException, when calling ClassLoader.getSystemClassLoader(),
     * in order to load the logger class.
     * 
     * Note, that since we call Security.getContext(), it too must lazily load
     * its loggers.
     * 
     * @return the logger
     */
    private static Logger getLogger() {
        synchronized (loggerLock){
            if (logger != null) return logger;
            logger = System.getLogger(CombinerSecurityManager.class.getName());
            return logger;
        }
    }
    private final DomainCombiner dc;
    // Cache of optimised Delegate AccessControlContext's
    private final ConcurrentMap<AccessControlContext, AccessControlContext> contextCache;
    private final ConcurrentMap<Object, NavigableSet<Permission>> checked;
    private final Guard g;
    private final Action action;
    private final Executor executor;
    private final Comparator<Referrer<Permission>> permCompare;
    private final AccessControlContext SMConstructorContext;
    private final AccessControlContext SMPrivilegedContext;
    private final ProtectionDomain privilegedDomain;
    private final boolean constructed;
    
    private static boolean check(){
        SecurityManager sm = System.getSecurityManager();
 	    if (sm != null) {
 		sm.checkPermission(new RuntimePermission("createSecurityManager"));
  	    }
        return true;
    } 
    
    public CombinerSecurityManager(){
        // Ensure we guard against finalizer attack by checking permission
        // before implicit super() Object constructor is called.
        this(check());
    }
    
    private CombinerSecurityManager(boolean check){
        super(); //checked the permission to create a SecurityManager.
	/* Get the policy & refresh, in case it hasn't been initialized. 
         * While there is no SecurityManager,
         * no policy checks are performed, however the policy must be in a
         * constructed working state, before the SecurityManager is set,
         * otherwise the Policy, if it's a non jvm policy, won't have permission
         * to read the properties and files it needs in order to be constructed.
	 * 
	 * Note: we don't want the sun policy provider by default because it
	 *	 cannot parse httpmd policy grants that don't have a message
	 *	 digest, only use it if specifically requested.
         */
	String policy_provider = System.getProperty("policy.provider");
	if (policy_provider == null || "sun.security.provider.PolicyFile".equals(policy_provider) )
	{
	    try {
		Policy.setPolicy(new ConcurrentPolicyFile());
	    } catch (PolicyInitializationException ex) {
		throw new ExceptionInInitializerError(ex);
	    }
	}
//        Policy policy = java.security.Policy.getPolicy(); 
	// Get context before this becomes a SecurityManager.
        SMConstructorContext = AccessController.getContext();
        ProtectionDomain [] context = new ProtectionDomain[1];
        privilegedDomain = this.getClass().getProtectionDomain();
        context[0] = privilegedDomain;
        SMPrivilegedContext = new AccessControlContext(context);
        dc = new DelegateDomainCombiner();
        ConcurrentMap<Referrer<AccessControlContext>, 
                Referrer<AccessControlContext>> internal = 
                new ConcurrentHashMap<Referrer<AccessControlContext>, 
                Referrer<AccessControlContext>>();
        contextCache = RC.concurrentMap(internal, Ref.TIME, Ref.STRONG, 60000L, 60000L);
        ConcurrentMap<Referrer<Object>, Referrer<NavigableSet<Permission>>> refmap 
                = new ConcurrentHashMap<Referrer<Object>, 
                Referrer<NavigableSet<Permission>>>();
        checked = RC.concurrentMap(refmap, Ref.TIME, Ref.STRONG, 20000L, 20000L);
        g = new SecurityPermission("getPolicy");
        action = new Action();
        // The intent here is to parallelise security checks as well as weed
        // out blocking SocketPermission's to execute them in parallel to 
        // reduce the wait on network IO.
        executor = Executors.newVirtualThreadPerTaskExecutor();
        permCompare = RC.comparator(new PermissionComparator());
        // This is to avoid unnecessarily refreshing the policy.
//        Permission createAccPerm = new SecurityPermission("createAccessControlContext");
//	if (!policy.implies(context[0], createAccPerm)) policy.refresh();
        /* Bug ID: 7093090 Reduce synchronization in java.security.Policy.getPolicyNoCheck
         * This bug may cause contention between ProtectionDomain implies
         * calls, also it could be a point of attack for Denial of service,
         * since the lock used is a static class lock.  This bug has been fixed
         * in jdk8(b15).
         */
	/* The following ensures the classes we need are loaded early to avoid
	 * class loading deadlock during permission checks */
	try {
	    checkPermission(new RuntimePermission("setIO"), SMPrivilegedContext);
	} catch (ExceptionInInitializerError er){
	    Error e = new ExceptionInInitializerError(
		"All domains on stack when starting a security manager must have AllPermission");
	    e.initCause(er);
	    throw e;
	}
	constructed = true;
    }
    
    /**
     * Throws a <code>SecurityException</code> if the requested
     * access, specified by the given permission, is not permitted based
     * on the security policy currently in effect.
     * 
     * This method obtains the current Security Context and checks
     * the give permission in that context.
     * 
     * @param perm
     * @throws SecurityException 
     */
    @Override
    public void checkPermission(Permission perm) throws SecurityException {
        Integer call = TRUSTED_RECURSIVE_CALL.isBound() ? TRUSTED_RECURSIVE_CALL.get() : null;
        if (call != null && call > 7) {
            /* This is a recursive permission check, there's a permission on
             * the stack that requires privilege to determine whether it is implied.
             * We can't continue indefinitely, as it will cause a stack overflow,
             * however we can allow a limited number of nested permission checks,
             * the same permission check may be repeated numerous times, in recursion.
             */
            throw new AccessControlException("Too many recursive permission checks", perm);
        }
        Object context = getSecurityContext();
        checkPermission(perm, context);
    }
      
    /**
     * Throws a <code>SecurityException</code> if the requested
     * access, specified by the given permission and context, is not permitted based
     * on the security policy currently in effect.
     * 
     * It is absolutely essential that the Security Context override equals 
     * and hashCode.
     * 
     * @param perm permission to be checked
     * @param context - AccessControlContext 
     * @throws SecurityException if context doesn't have permission.
     */
    @Override
    public final void checkPermission(Permission perm, Object context) throws SecurityException {
        if (perm == null ) throw new NullPointerException("Permission Collection null");
	perm.getActions(); // Ensure any lazy state has been instantiated before publication.
        AccessControlContext executionContext = null;
	if (context instanceof AccessControlContext){
            executionContext = (AccessControlContext) context;
        } else {
            throw new SecurityException();
        }
        /* The next line speeds up permission checks related to this SecurityManager. */
        if ( constructed
		&& (SMPrivilegedContext.equals(executionContext)
		|| SMConstructorContext.equals(executionContext) 
		)
            ) return; // prevents endless loop in debug.
        Integer count = TRUSTED_RECURSIVE_CALL.isBound() ? TRUSTED_RECURSIVE_CALL.get() : null;
        if (count == null) count = Integer.valueOf(0);
        // Checks if Permission has already been checked for this context.
        NavigableSet<Permission> checkedPerms = checked.get(context);
        if (checkedPerms == null){
            /* A ConcurrentSkipListSet is used to avoid blocking during
             * removal operations that occur while the garbage collector
             * recovers softly reachable memory.  Since this happens while
             * the jvm's under stress, it's important that permission checks
             * continue to perform well.
             * 
             * Although I considered a multi read, single write Set, I wanted
             * to avoid blocking under stress, that would be caused as a result
             * of garbage collection.
             * 
             * IMPORTANT:
             * The Set "checkedPerms" must be obtained prior to executing a permission
             * check and the result written to the same Set, interleaved
             * clear operations may remove the Set from the ConcurrentMap "checked",
             * this prevents revoked permissions from entering the "checked"
             * cache after clear is called and allows tasks to run to completion 
             * without needing to be concerned about revocation.
             */
            NavigableSet<Referrer<Permission>> internal = 
                    new ConcurrentSkipListSet<Referrer<Permission>>(permCompare);
            checkedPerms = RC.navigableSet(internal, Ref.TIME, 10000L);
            final NavigableSet<Permission> perms = checkedPerms;
            NavigableSet<Permission> existed = ScopedValue.where(TRUSTED_RECURSIVE_CALL, count + 1).call(
                new CallableOp<NavigableSet<Permission>, SecurityException>(){
                    @Override
                    public NavigableSet<Permission> call() throws SecurityException {
                        return checked.putIfAbsent(context, perms);
                    }
                });
            if (existed != null) checkedPerms = existed;
        }
        if (checkedPerms.contains(perm)) return; // don't need to check again.
        // Cache the created AccessControlContext.
        AccessControlContext delegateContext = contextCache.get(executionContext);
        if (delegateContext == null ) {
            final AccessControlContext finalExecutionContext = executionContext;
            // Create a new AccessControlContext with the DelegateDomainCombiner
            delegateContext = ScopedValue.where(TRUSTED_RECURSIVE_CALL, count + 1).call(
            new CallableOp<AccessControlContext, SecurityException>(){
                @Override
                public AccessControlContext call() throws SecurityException {
                    return AccessController.doPrivileged( 
                        new PrivilegedAction<AccessControlContext>(){
                            public AccessControlContext run() {
                                return AccessControlContext.build(finalExecutionContext, dc);
                            }
                        }
                    );
                }
            });
            // Optimise the delegateContext, this runs the DelegateDomainCombiner
            // and returns the AccessControlContext.
            // This is a mutator method, the delegateContext returned
            // is actually the same object passed in, after it is
            // mutated, but just in case that changes in future we
            // return it.
            delegateContext = AccessController.doPrivileged(action, delegateContext);
            final AccessControlContext delContext = delegateContext;
            
            ScopedValue.where(TRUSTED_RECURSIVE_CALL, count + 1).call(
                new CallableOp<AccessControlContext, SecurityException>(){
                    @Override
                    public AccessControlContext call() throws SecurityException {
                        return contextCache.putIfAbsent(finalExecutionContext, delContext);
                    }
                }
            );
        }
        // Normal execution, same as SecurityManager.
        delegateContext.checkPermission(perm); // Throws SecurityException.
        /* It's ok to cache SocketPermission if we use a comparator */
        // If we get to here, no exceptions were thrown, caller has permission.
        checkedPerms.add(perm);
    }
    
    /**
     * This method is intended to be called only by a Policy.
     * 
     * To clear the cache of checked Permissions requires the following Permission:
     * java.security.SecurityPermission("getPolicy");
     * 
     * @throws SecurityException if caller isn't permitted to clear cache.
     */
    @Override
    public void clearCache() throws SecurityException {
        /* Clear the cache, out of date permission check tasks are still
         * writing to old Set's, while new checks will write to new Sets.
         */
        g.checkGuard(this);
        Integer count = TRUSTED_RECURSIVE_CALL.isBound() ? TRUSTED_RECURSIVE_CALL.get() : null;
        if (count == null) count = Integer.valueOf(0);
        ScopedValue.where(TRUSTED_RECURSIVE_CALL, count + 1).call(
            new CallableOp<Boolean, SecurityException>(){
                @Override
                public Boolean call() throws SecurityException {
                    checked.clear();
                    return true;
                }
            }
        );
    }
    
    // Action retrieves the optimised AccessControlContext.
    private static class Action implements PrivilegedAction<AccessControlContext> {
        private Action(){}
        
        public AccessControlContext run(){
            return AccessController.getContext();
        }
        
    }
    
    private class DelegateDomainCombiner implements DomainCombiner {
        
        private DelegateDomainCombiner (){
        }

        public ProtectionDomain[] combine(final ProtectionDomain[] currentDomains, final ProtectionDomain[] assignedDomains) {
            /* We're only interested in the assignedDomains, since these
             * are from the Context that the SecurityManager has been asked
             * to check.
             * 
             * assignedDomains are inherited domains.
             * 
             * This code wraps assignedDomains in a DelegateProtectionDomain
             * to ensure we check for the DelegatePermission or it's candidate
             * Permission.
             * 
             * The AccessControlContext instance will be the new instance
             * we just created moments earlier, but with the context returned
             * by this DomainCombiner.
             *
             * The SecurityManager's ProtectionDomain must be removed
             * from the Context, for the following case:
             * 
             * If using sun.security.provider.PolicyFile, the policy will
             * cache it's own domain prior to it being instantiated and it
             * may perform a PrivilegedAction when it's 
             * getPermissions(ProtectionDomain pd) is later called for
             * ProtectionDomain's not in policy cache.
             * However, CombinerSecurityManager and
             * net.jini.security.Security cannot cache their shared 
             * ProtectionDomain, relying on the underlying policy instead.
             * 
             * When a standard java permission check
             * is made, the AccessController picks up the domain of 
             * CombinerSecurityManager and net.jini.security.Security,
             * as well as that of the policy provider.  Since the policy
             * provider will cache it's own ProtectionDomain, but not that
             * of the SecurityManager and Security, a infinite circular call 
             * loop will preceed until a StackOverflowError occurs.
             * 
             * This will be caused by PolicyFile, attempting to determine
             * which permissions apply to the ProtectionDomain of
             * CombinerSecurityManager and Security, then asking
             * the SecurityManager if it has a FilePermission.
             * 
             * The policy provider org.apache.river.security.ConcurrentPolicyFile
             * has no such issue, unless using CodeSource based PermissionGrant's,
             * which have been deprecated.
             */
            int l = assignedDomains != null ? assignedDomains.length : 0;
            List<ProtectionDomain> list = new ArrayList<ProtectionDomain>(l);
            for (int i = 0; i < l ; i++){
                if (assignedDomains[i] != privilegedDomain && assignedDomains[i] != null){
                    list.add(assignedDomains[i]);
                }
            }
            ProtectionDomain [] context = list.toArray(new ProtectionDomain[list.size()]);
            DelegateProtectionDomain[] delegated = new DelegateProtectionDomain[1];
            delegated[0] = new DelegateProtectionDomain(context);
            return delegated;
        }
    }
    
    /*
     * DelegateProtectionDomain executes checks on ProtectionDomain's in parallel.
     */
    private class DelegateProtectionDomain extends ProtectionDomain {
        // Context from AccessControlContext.
        private final ProtectionDomain[] context;
        
        DelegateProtectionDomain(ProtectionDomain[] context){
            // Use static domain so we don't strongly reference the ClassLoader
            // which has a strong reference to ProtectionDomain.
            super(null, null);
            this.context = context; // Not mutated so don't need to clone.
        }
        
        /* An earlier implementation used interruption to cancel running tasks,
         * this interruption only added complexity, in most cases permission
         * checks are expected to pass and failure occurs far less often, 
         * for that reason, it is acceptable for all tasks to run to completion.  
         * The overall performance cost of using task interruption was likely 
         * greater, due to increased access of shared memory for only a small
         * performance benefit for failling permission checks.
         * 
         * If the current thread is interrupted, the interrupt status is
         * preserved, this is done in cases where permission is required to perform
         * safe shutdown
         */
        @Override
        public boolean implies(Permission perm) {
            Thread currentThread = Thread.currentThread();
            boolean interrupt = Thread.interrupted(); // Clears the interrupt and stores it.
            int l = context.length;
            /* This is both a performance optimisation and a safety precaution.
             * When there are only a few domains on the stack, they are 
             * normally privileged and will return very quickly.
             * 
             * Also, permission checks performed inside PrivilegedAction
             * calls by the Policy may come from setting or getting context security
             * sensitive variables when wrappingPrivilegedAction
             * permission checks.
             * 
             * The policy may accept Objects from other ProtectionDomain's
             * as part of a PermissionGrant, this domain must be included
             * in the context so it can be checked, but since that would
             * create a recursive call, we avoid recursion
             * by not splitting that permission check among multiple threads.
             */
            if ( l < 4 ){ 
                for ( int i = 0; i < l; i++ ){
                    if (! checkPermission(context[i], perm)) {
                        if (interrupt) currentThread.interrupt();
                        return false;
                    }
                }
                if (interrupt) currentThread.interrupt();
                return true;
            }
            CountDownLatch latch = new CountDownLatch(l);
            List<RunnableFuture<Boolean>> resultList = new ArrayList<RunnableFuture<Boolean>>(l);
            for ( int i = 0; i < l; i++ ){
                resultList.add(new FutureTask<Boolean>(
                    new PermissionCheck(context[i], perm, latch)
                ));
            }
            Iterator<RunnableFuture<Boolean>> it = resultList.iterator();
            while (it.hasNext()){
                executor.execute(it.next());
            }
            try {
                // We can change either call to add a timeout.
                if (!latch.await(180L, TimeUnit.SECONDS)) return false; // Throws InterruptedException
                it = resultList.iterator();
                try {
                    while (it.hasNext()){
                            Boolean result = it.next().get(); // Throws InterruptedException
                            if (result.equals(Boolean.FALSE)) {
                                if (interrupt) currentThread.interrupt();
                                return false;
                            }
                    }
                    if (interrupt) currentThread.interrupt();
                    return true;
                } catch (ExecutionException ex) {
                    // This should never happen, unless a runtime exception occurs.
                    if (getLogger().isLoggable(Level.ERROR)) getLogger().log(Level.DEBUG, "Unexpected exception", ex);
                    throw new RuntimeException("Unrecoverable: ", ex.getCause()); // Bail out.
                }
            } catch (InterruptedException ex) {
                // REMIND: Java Memory Model and thread interruption.           
                // We've been externally interrupted, during execution.
                // Do this the slow way to avoid reinterruption during shutdown cleanup!
                if (getLogger().isLoggable(Level.DEBUG)) getLogger().log(Level.DEBUG, "External Interruption", ex);
                for ( int i = 0; i < l; i++ ){
                    if (!checkPermission(context[i], perm)) {
                        currentThread.interrupt(); // restore external interrupt.
                        return false;
                    }
                }
                currentThread.interrupt(); // restore external interrupt.
                return true;
            }
        }
        
        @Override
        public String toString(){
            /* Unfortunately we don't know exactly which domain has failed
             * in fact, multiple domains may fail the permission check since
             * they are executed concurrently, for that reason, we'll print
             * all domains on the stack.
             */
            StringBuilder sb = new StringBuilder(800);
            sb.append("DomainCombinerSecurityManager full stack: \n");
            int l = context.length;
            for (int i = 0; i < l; i++ ){
                sb.append(context[i].toString());
            }
            return sb.toString();
        }
        
    }
    
    /**
     * Immutable callable task, discarded immediately after use.
     */
    private class PermissionCheck implements Callable<Boolean> {
        private final ProtectionDomain pd;
        private final Permission p;
        private final CountDownLatch latch;
        
        PermissionCheck(ProtectionDomain pd, Permission p, CountDownLatch c){
            if (pd == null || p == null) throw new NullPointerException();
            this.pd = pd;
            this.p = p;
            latch = c;
            
        }

        public Boolean call() throws Exception {
            try {
                Boolean result = AccessController.doPrivileged( 
                    new PrivilegedAction<Boolean>(){
                        public Boolean run() {
                            boolean result = checkPermission(pd, p);
                            return Boolean.valueOf(result);
                        }
                    }  
                );
                return result;
            } finally {
                // In case we exit with a runtime exception, ensure threads
                // aren't left waiting.
                latch.countDown();
            }
        }
        
    }
    
    /**
     * Enables customisation of permission check.
     * @param pd protection domain to be checked.
     * @param p permission to be checked.
     * @return true if ProtectionDomain pd has Permission p.
     */
    protected boolean checkPermission(ProtectionDomain pd, Permission p){
        return pd.implies(p);
    }
    
}
