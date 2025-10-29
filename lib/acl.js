var Permission = require('./permission');
var PermissionType = require('./permission_type');

function Acl() {
  this.permissions = [];
  this.roles = {};
  this.resources = {};
}

Acl.prototype.addRole = function(role, parent) {
  this.roles[role] = parent || null;
};

Acl.prototype.addResource = function(resource, parent) {
  this.resources[resource] = parent || null;
};

Acl.prototype.allow = function(role, resource, actions, assertion) {
  if (!isArray(actions)) actions = [actions];
  for (var i in actions)
    this.permissions.push(new Permission(role || null, resource || null, actions[i] || null, assertion || true, PermissionType.ALLOW));
};

Acl.prototype.deny = function(role, resource, actions, assertion) {
  if (!isArray(actions)) actions = [actions];
  for (var i in actions)
    this.permissions.push(new Permission(role || null, resource || null, actions[i] || null, assertion || false, PermissionType.DENY));
};

// kibi: Where "done" is a callback function with following signature 
// function(err, allowed, permissionType)
Acl.prototype.query = function(role, resource, action, done) {
  // LIFO
  var roles
    , resources
    , matches = []
    , extractedRole = extractRole(role);

  // LIFO loop, starting with specified role/resource and moving up through parents
  roles = isArray(extractedRole)
    ? getParentRolesFromArray.call(this, extractedRole)
    : getParentRoles.call(this, extractedRole);

  resources = getParentResources.call(this, resource);
  
  
  // Note: 
  // Instead of creating the permission list 
  // and then evaluating it we evaluate right away in LIFO order 
  // The logic is the same as original however we avoid creating extra objects 
  // and iterating second time over the matched permissions 
  // this also avoids setTimeout from PermissionList 
  let permIndex = this.permissions.length - 1
  
  const next = () => {
    // advance to next matching rule (LIFO)
    for (; permIndex >= 0; permIndex--) {
      for (let roleIndex = 0; roleIndex < roles.length; roleIndex++) {
        for (let resourceIndex = 0; resourceIndex < resources.length; resourceIndex++) {
          const p = this.permissions[permIndex];
          if (p.match(roles[roleIndex] || null, resources[resourceIndex] || null, action || null)) {
            permIndex--; // consume this rule; next() will pick up after it
            // If the rule is boolean, query() will call done() sync; we STOP here.
            // If it's a function, it will schedule async and call next() (this closure) later.
            return p.query(role, resource, action, done, next);
          }
        }
      }
    }
    // no matches → INHERIT
    done(null, false, PermissionType.INHERIT);
  };
  next();
};

// Private
var getParentRolesFromArray = function(role) {
  var roles = [];
  for (var i in role) {
    var parentRoles = getParentRoles.call(this, role[i]);
    parentRoles = parentRoles.filter(function (item, pos) { return roles.indexOf(item) < 0 });
    roles = roles.concat(parentRoles);
  }

  return roles;
}

var getParentRole = function(role) {
  return this.roles[role] || null;
};

var getParentRoles = function(role) {
  var roles = [];

  do {
    roles.push(role);
  } while (role = getParentRole.call(this, role));

  return roles;
};

var getParentResources = function(resource) {
  var resources = [];

  do {
    resources.push(resource);
  } while (resource = getParentResource.call(this, resource));

  return resources;
};

var getParentResource = function(resource) {
  return this.resources[resource] || null;
};

var isArray = Array.isArray || function (vArg) {
  return Object.prototype.toString.call(vArg) === "[object Array]";
};

function extractRole(role) {
  if (typeof(role) == 'string' || isArray(role)) {
    return role;
  } else if (null === role) {
    return null;
  } else if (typeof(role.getRoleId) == 'function') {
    return role.getRoleId();
  } else if (typeof(role.role_id) == 'string' || isArray(role.role_id)) {
    return role.role_id;
  } else {
    throw "Unable to determine role";
  }
};

module.exports = Acl;
