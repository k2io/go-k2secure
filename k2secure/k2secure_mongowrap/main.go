// Copyright (C) 2022 K2 Cyber Security Inc.

package k2secure_mongowrap

import (
	"context"

	k2i "github.com/k2io/go-k2secure/v2/k2secure_intercept"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var logger = k2i.GetLogger("mongohook")

type K2Collectionstruct struct {
	mongo.Collection
}

//WrapInterface Hook ------------------------------------
//go:noinline
func (coll *K2Collectionstruct) K2mongoCollectionInsertOne_s(ctx context.Context, documents interface{}, opts ...*options.InsertOneOptions) (*mongo.InsertOneResult, error) {
	logger.Debugln("------------ K2mongoCollectionInsertOne_s" + "in hook")
	if documents != nil {
		k2i.K2nosqlExec(getParam(documents, ""), "insert")
	}
	a, b := coll.K2mongoCollectionInsertOne_s(ctx, documents, opts...)
	return a, b
}

//go:noinline
func (coll *K2Collectionstruct) K2mongoCollectionInsertOne(ctx context.Context, documents interface{}, opts ...*options.InsertOneOptions) (*mongo.InsertOneResult, error) {
	logger.Debugln("------------ K2mongoCollectionInsertOne" + "in hook")
	var eventID = k2i.GetDummyEvent()
	if documents != nil {
		eventID = k2i.K2nosqlExec(getParam(documents, ""), "insert")
	}
	a, err := coll.K2mongoCollectionInsertOne_s(ctx, documents, opts...)
	k2i.SendExitEvent(eventID, err)
	return a, err
}

//go:noinline
func (coll *K2Collectionstruct) K2mongoCollectionInsertMany_s(ctx context.Context, documents []interface{}, opts ...*options.InsertManyOptions) (*mongo.InsertManyResult, error) {
	logger.Debugln("------------ k2mongoCollectionInsertMany_s-hook" + "in hook")
	if documents != nil {
		k2i.K2nosqlExec(getParam(documents, ""), "insert")
	}
	result, err := coll.K2mongoCollectionInsertMany_s(ctx, documents, opts...)
	return result, err
}

//go:noinline
func (coll *K2Collectionstruct) K2mongoCollectionInsertMany(ctx context.Context, documents []interface{}, opts ...*options.InsertManyOptions) (*mongo.InsertManyResult, error) {
	logger.Debugln("------------ k2mongoCollectionInsertMany-hook" + "in hook")
	var eventID = k2i.GetDummyEvent()
	if documents != nil {
		eventID = k2i.K2nosqlExec(getParam(documents, ""), "insert")
	}
	result, err := coll.K2mongoCollectionInsertMany_s(ctx, documents, opts...)
	k2i.SendExitEvent(eventID, err)
	return result, err
}

//go:noinline
func (coll *K2Collectionstruct) K2mongoCollectionDeleteOne_s(ctx context.Context, filter interface{}, opts ...*options.DeleteOptions) (*mongo.DeleteResult, error) {
	logger.Debugln("------------ k2mongoCollectionDeleteMany_s-hook" + "in hook")
	if filter != nil {
		k2i.K2nosqlExec(getParam(filter, ""), "delete")
	}
	result, err := coll.K2mongoCollectionDeleteOne_s(ctx, filter, opts...)
	return result, err
}

//go:noinline
func (coll *K2Collectionstruct) K2mongoCollectionDeleteOne(ctx context.Context, filter interface{}, opts ...*options.DeleteOptions) (*mongo.DeleteResult, error) {
	logger.Debugln("------------ k2mongoCollectionDeleteMany-hook" + "in hook")
	var eventID = k2i.GetDummyEvent()
	if filter != nil {
		eventID = k2i.K2nosqlExec(getParam(filter, ""), "delete")
	}
	result, err := coll.K2mongoCollectionDeleteOne_s(ctx, filter, opts...)
	k2i.SendExitEvent(eventID, err)
	return result, err
}

//go:noinline
func (coll *K2Collectionstruct) K2mongoCollectionDeleteMany_s(ctx context.Context, filter interface{}, opts ...*options.DeleteOptions) (*mongo.DeleteResult, error) {
	logger.Debugln("------------ k2mongoCollectionDeleteOne_s-hook" + "in hook")
	if filter != nil {
		k2i.K2nosqlExec(getParam(filter, ""), "delete")
	}
	result, err := coll.K2mongoCollectionDeleteMany_s(ctx, filter, opts...)
	return result, err
}

//go:noinline
func (coll *K2Collectionstruct) K2mongoCollectionDeleteMany(ctx context.Context, filter interface{}, opts ...*options.DeleteOptions) (*mongo.DeleteResult, error) {
	logger.Debugln("------------ k2mongoCollectionDeleteOne-hook" + "in hook")
	var eventID = k2i.GetDummyEvent()
	if filter != nil {
		eventID = k2i.K2nosqlExec(getParam(filter, ""), "delete")
	}
	result, err := coll.K2mongoCollectionDeleteMany_s(ctx, filter, opts...)
	k2i.SendExitEvent(eventID, err)
	return result, err
}

//go:noinline
func (coll *K2Collectionstruct) K2mongoCollectionUpdateOne_s(ctx context.Context, filter interface{}, update interface{},
	opts ...*options.UpdateOptions) (*mongo.UpdateResult, error) {
	logger.Debugln("------------ k2mongoCollectionUpdateOne_s" + "in hook")
	if filter != nil && update != nil {
		k2i.K2nosqlExec(getParam(filter, update), "update")
	}
	result, err := coll.K2mongoCollectionUpdateOne_s(ctx, filter, update, opts...)
	return result, err
}

//go:noinline
func (coll *K2Collectionstruct) K2mongoCollectionUpdateOne(ctx context.Context, filter interface{}, update interface{}, opts ...*options.UpdateOptions) (*mongo.UpdateResult, error) {
	logger.Debugln("------------ k2mongoCollectionUpdateOne-hook" + "in hook")
	var eventID = k2i.GetDummyEvent()
	if filter != nil && update != nil {
		eventID = k2i.K2nosqlExec(getParam(filter, update), "update")
	}
	result, err := coll.K2mongoCollectionUpdateOne_s(ctx, filter, update, opts...)
	k2i.SendExitEvent(eventID, err)
	return result, err
}

//go:noinline
func (coll *K2Collectionstruct) K2mongoCollectionUpdateMany_s(ctx context.Context, filter interface{}, update interface{}, opts ...*options.UpdateOptions) (*mongo.UpdateResult, error) {
	logger.Debugln("------------ k2mongoCollectionUpdateMany_s-hook" + "in hook")
	if filter != nil && update != nil {
		k2i.K2nosqlExec(getParam(filter, update), "update")
	}
	result, err := coll.K2mongoCollectionUpdateMany_s(ctx, filter, update, opts...)
	return result, err
}

//go:noinline
func (coll *K2Collectionstruct) K2mongoCollectionUpdateMany(ctx context.Context, filter interface{}, update interface{}, opts ...*options.UpdateOptions) (*mongo.UpdateResult, error) {
	logger.Debugln("------------ k2mongoCollectionUpdateMany-hook" + "in hook")
	var eventID = k2i.GetDummyEvent()
	if filter != nil && update != nil {
		eventID = k2i.K2nosqlExec(getParam(filter, update), "update")
	}
	result, err := coll.K2mongoCollectionUpdateMany_s(ctx, filter, update, opts...)
	k2i.SendExitEvent(eventID, err)
	return result, err
}

//go:noinline
func (coll *K2Collectionstruct) K2mongoCollectionReplaceOne_s(ctx context.Context, filter interface{}, replacement interface{}, opts ...*options.ReplaceOptions) (*mongo.UpdateResult, error) {
	logger.Debugln("------------ k2mongoCollectionReplaceOne_s-hook" + "in hook")
	if filter != nil && replacement != nil {
		k2i.K2nosqlExec(getParam(filter, replacement), "update")
	}
	result, err := coll.K2mongoCollectionReplaceOne_s(ctx, filter, replacement, opts...)
	return result, err
}

//go:noinline
func (coll *K2Collectionstruct) K2mongoCollectionReplaceOne(ctx context.Context, filter interface{}, replacement interface{}, opts ...*options.ReplaceOptions) (*mongo.UpdateResult, error) {
	logger.Debugln("------------ k2mongoCollectionReplaceOne-hook" + "in hook")
	var eventID = k2i.GetDummyEvent()
	if filter != nil && replacement != nil {
		eventID = k2i.K2nosqlExec(getParam(filter, replacement), "update")
	}
	result, err := coll.K2mongoCollectionReplaceOne_s(ctx, filter, replacement, opts...)
	k2i.SendExitEvent(eventID, err)
	return result, err
}

//go:noinline
func (coll *K2Collectionstruct) K2mongoCollectionFind_s(ctx context.Context, filter interface{}, opts ...*options.FindOptions) (*mongo.Cursor, error) {
	logger.Debugln("------------ k2mongoCollectionFind_s-hook" + "in hook")
	if filter != nil {
		k2i.K2nosqlExec(getParam(filter, ""), "find")
	}
	cur, err := coll.K2mongoCollectionFind_s(ctx, filter, opts...)
	return cur, err
}

//go:noinline
func (coll *K2Collectionstruct) K2mongoCollectionFind(ctx context.Context, filter interface{}, opts ...*options.FindOptions) (*mongo.Cursor, error) {
	logger.Debugln("------------ k2mongoCollectionFind-hook" + "in hook")
	var eventID = k2i.GetDummyEvent()
	if filter != nil {
		eventID = k2i.K2nosqlExec(getParam(filter, ""), "find")
	}
	cur, err := coll.K2mongoCollectionFind_s(ctx, filter, opts...)
	k2i.SendExitEvent(eventID, err)
	return cur, err
}

//go:noinline
func (coll *K2Collectionstruct) K2mongoCollectionFindOneAndDelete_s(ctx context.Context, filter interface{}, opts ...*options.FindOneAndDeleteOptions) *mongo.SingleResult {
	logger.Debugln("------------ k2mongoCollectionFindOneDelete_s-hook" + "in hook")
	if filter != nil {
		k2i.K2nosqlExec(getParam(filter, ""), "delete")
	}
	result := coll.K2mongoCollectionFindOneAndDelete_s(ctx, filter, opts...)
	return result
}

//go:noinline
func (coll *K2Collectionstruct) K2mongoCollectionFindOneAndDelete(ctx context.Context, filter interface{}, opts ...*options.FindOneAndDeleteOptions) *mongo.SingleResult {
	logger.Debugln("------------ k2mongoCollectionFindOneDelete-hook" + "in hook")
	var eventID = k2i.GetDummyEvent()
	if filter != nil {
		eventID = k2i.K2nosqlExec(getParam(filter, ""), "delete")
	}
	result := coll.K2mongoCollectionFindOneAndDelete_s(ctx, filter, opts...)
	if result != nil {
		k2i.SendExitEvent(eventID, nil)
	}
	return result
}

//go:noinline
func (coll *K2Collectionstruct) K2mongoCollectionFindOneAndReplace_s(ctx context.Context, filter interface{}, replacement interface{}, opts ...*options.FindOneAndReplaceOptions) *mongo.SingleResult {
	logger.Debugln("------------ k2mongoCollectionFindOneReplace_s-hook" + "in hook")
	if filter != nil {
		k2i.K2nosqlExec(getParam(filter, replacement), "update")
	}
	result := coll.K2mongoCollectionFindOneAndReplace_s(ctx, filter, replacement, opts...)
	return result
}

//go:noinline
func (coll *K2Collectionstruct) K2mongoCollectionFindOneAndReplace(ctx context.Context, filter interface{}, replacement interface{}, opts ...*options.FindOneAndReplaceOptions) *mongo.SingleResult {
	logger.Debugln("------------ k2mongoCollectionFindOneReplace-hook" + "in hook")
	var eventID = k2i.GetDummyEvent()
	if filter != nil {
		eventID = k2i.K2nosqlExec(getParam(filter, replacement), "update")
	}
	result := coll.K2mongoCollectionFindOneAndReplace_s(ctx, filter, replacement, opts...)
	if result != nil {
		k2i.SendExitEvent(eventID, nil)
	}
	return result
}

//go:noinline
func (coll *K2Collectionstruct) K2mongoCollectionFindOneAndUpdate_s(ctx context.Context, filter interface{}, update interface{}, opts ...*options.FindOneAndUpdateOptions) *mongo.SingleResult {
	logger.Debugln("------------ k2mongoCollectionFindOneUpdate_s-hook" + "in hook")
	if filter != nil {
		k2i.K2nosqlExec(getParam(filter, update), "update")
	}
	result := coll.K2mongoCollectionFindOneAndUpdate_s(ctx, filter, update, opts...)
	return result
}

//go:noinline
func (coll *K2Collectionstruct) K2mongoCollectionFindOneAndUpdate(ctx context.Context, filter interface{}, update interface{}, opts ...*options.FindOneAndUpdateOptions) *mongo.SingleResult {
	logger.Debugln("------------ k2mongoCollectionFindOneUpdate-hook" + "in hook")
	var eventID = k2i.GetDummyEvent()
	if filter != nil {
		eventID = k2i.K2nosqlExec(getParam(filter, update), "update")
	}
	result := coll.K2mongoCollectionFindOneAndUpdate_s(ctx, filter, update, opts...)
	if result != nil {
		k2i.SendExitEvent(eventID, nil)
	}
	return result
}

func getParam(f, g interface{}) []byte {
	tmp_map := map[string]interface{}{
		"filter":  f,
		"options": g,
	}
	map_json, err := bson.MarshalExtJSON(tmp_map, true, true)
	if err != nil {
		logger.Errorln("Error During MarshalExtJSON ", tmp_map)
		return []byte("")
	} else {
		return map_json
	}
}

func PluginStart() {

	if k2i.DropHook_mongo() {
		return
	}
	//insert
	e := k2i.HookWrapInterface((*mongo.Collection).InsertMany, (*K2Collectionstruct).K2mongoCollectionInsertMany, (*K2Collectionstruct).K2mongoCollectionInsertMany_s)
	k2i.IsHookedLog("(*mongo.Collection).InsertMany", e)

	e = k2i.HookWrapInterface((*mongo.Collection).InsertOne, (*K2Collectionstruct).K2mongoCollectionInsertOne, (*K2Collectionstruct).K2mongoCollectionInsertOne_s)
	k2i.IsHookedLog("(*mongo.Collection).InsertOne", e)
	//find
	e = k2i.HookWrapInterface((*mongo.Collection).Find, (*K2Collectionstruct).K2mongoCollectionFind, (*K2Collectionstruct).K2mongoCollectionFind_s)
	k2i.IsHookedLog("(*mongo.Collection).Find", e)
	e = k2i.HookWrapInterface((*mongo.Collection).FindOneAndReplace, (*K2Collectionstruct).K2mongoCollectionFindOneAndReplace, (*K2Collectionstruct).K2mongoCollectionFindOneAndReplace_s)
	k2i.IsHookedLog("(*mongo.Collection).FindOneAndReplace", e)
	e = k2i.HookWrapInterface((*mongo.Collection).FindOneAndUpdate, (*K2Collectionstruct).K2mongoCollectionFindOneAndUpdate, (*K2Collectionstruct).K2mongoCollectionFindOneAndUpdate_s)
	k2i.IsHookedLog("(*mongo.Collection).FindOneAndUpdate", e)
	e = k2i.HookWrapInterface((*mongo.Collection).FindOneAndDelete, (*K2Collectionstruct).K2mongoCollectionFindOneAndDelete, (*K2Collectionstruct).K2mongoCollectionFindOneAndDelete_s)
	k2i.IsHookedLog("(*mongo.Collection).FindOneAndDelete", e)

	//update
	e = k2i.HookWrapInterface((*mongo.Collection).UpdateOne, (*K2Collectionstruct).K2mongoCollectionUpdateOne, (*K2Collectionstruct).K2mongoCollectionUpdateOne_s)
	k2i.IsHookedLog("(*mongo.Collection).UpdateOne", e)
	e = k2i.HookWrapInterface((*mongo.Collection).UpdateMany, (*K2Collectionstruct).K2mongoCollectionUpdateMany, (*K2Collectionstruct).K2mongoCollectionUpdateMany_s)
	k2i.IsHookedLog("(*mongo.Collection).UpdateMany", e)

	//ReplaceOne
	e = k2i.HookWrapInterface((*mongo.Collection).ReplaceOne, (*K2Collectionstruct).K2mongoCollectionReplaceOne, (*K2Collectionstruct).K2mongoCollectionReplaceOne_s)
	k2i.IsHookedLog("(*mongo.Collection).ReplaceOne", e)

	// Delete
	e = k2i.HookWrapInterface((*mongo.Collection).DeleteOne, (*K2Collectionstruct).K2mongoCollectionDeleteOne, (*K2Collectionstruct).K2mongoCollectionDeleteOne_s)
	k2i.IsHookedLog("(*mongo.Collection).DeleteOne", e)
	e = k2i.HookWrapInterface((*mongo.Collection).DeleteMany, (*K2Collectionstruct).K2mongoCollectionDeleteMany, (*K2Collectionstruct).K2mongoCollectionDeleteMany_s)
	k2i.IsHookedLog("(*mongo.Collection).DeleteMany", e)
}
func init() {
	if k2i.K2OK("k2secure_mongo.init") == false {
		return
	}
	if k2i.IsK2Disable() {
		return
	}
	PluginStart()
}
