// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// +build docker

package collectors

import (
	"context"
	"fmt"
	"time"

	"github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/errors"
	"github.com/DataDog/datadog-agent/pkg/tagger/utils"
	taggerutil "github.com/DataDog/datadog-agent/pkg/tagger/utils"
	"github.com/DataDog/datadog-agent/pkg/util/containers"
	"github.com/DataDog/datadog-agent/pkg/util/log"

	ecsutil "github.com/DataDog/datadog-agent/pkg/util/ecs"
	ecsmeta "github.com/DataDog/datadog-agent/pkg/util/ecs/metadata"
	v1 "github.com/DataDog/datadog-agent/pkg/util/ecs/metadata/v1"
	v3 "github.com/DataDog/datadog-agent/pkg/util/ecs/metadata/v3"
)

const (
	ecsCollectorName = "ecs"
	ecsExpireFreq    = 5 * time.Minute
)

// ECSCollector listen to the ECS agent to get ECS metadata.
// Relies on the DockerCollector to trigger deletions, it's not intended to run standalone
type ECSCollector struct {
	infoOut     chan<- []*TagInfo
	expire      *taggerutil.Expire
	lastExpire  time.Time
	expireFreq  time.Duration
	metaV1      *v1.Client
	clusterName string
}

// Detect tries to connect to the ECS agent
func (c *ECSCollector) Detect(ctx context.Context, out chan<- []*TagInfo) (CollectionMode, error) {
	if ecsutil.IsFargateInstance(ctx) {
		return NoCollection, fmt.Errorf("ECS collector is disabled on Fargate")
	}

	metaV1, err := ecsmeta.V1()
	if err != nil {
		return NoCollection, err
	}

	c.metaV1 = metaV1
	c.infoOut = out
	c.lastExpire = time.Now()
	c.expireFreq = ecsExpireFreq

	c.expire, err = taggerutil.NewExpire(ecsExpireFreq)
	if err != nil {
		return NoCollection, err
	}

	instance, err := c.metaV1.GetInstance(ctx)
	if err != nil {
		log.Warnf("Cannot determine ECS cluster name: %s", err)
	}

	c.clusterName = instance.Cluster

	return FetchOnlyCollection, nil
}

// Fetch fetches ECS tags
func (c *ECSCollector) Fetch(ctx context.Context, entity string) ([]string, []string, []string, error) {
	entityType, cID := containers.SplitEntityName(entity)
	if entityType != containers.ContainerEntityName || len(cID) == 0 {
		return nil, nil, nil, nil
	}

	tasks, err := c.metaV1.GetTasks(ctx)
	if err != nil {
		return []string{}, []string{}, []string{}, err
	}

	var updates []*TagInfo

	if config.Datadog.GetBool("ecs_collect_resource_tags_ec2") && ecsutil.HasEC2ResourceTags() {
		updates, err = c.parseTasks(ctx, tasks, cID, addTagsForContainer)
	} else {
		updates, err = c.parseTasks(ctx, tasks, cID)
	}
	if err != nil {
		return []string{}, []string{}, []string{}, err
	}

	c.infoOut <- updates

	// Only run the expire process with the most up to date tasks parsed.
	// Using a go routine as the expire process can be done asynchronously.
	// We do not use the output as the ECSCollector is not meant run in standalone.
	if time.Now().Sub(c.lastExpire) >= c.expireFreq {
		go c.expire.ComputeExpires() //nolint:errcheck
		c.lastExpire = time.Now()
	}

	for _, info := range updates {
		if info.Entity == entity {
			// this TagInfo is sent to c.infoOut too, but there is
			// no guarantee that it will be processed before or
			// after consumers of Fetch get the tags returned here.
			// To prevent a cached TagInfo with an expiry date from
			// being overwritten with one without, we need to
			// somehow return an error here.
			var err error
			if !info.ExpiryDate.IsZero() {
				err = errors.NewPartial(entity)
			}

			return info.LowCardTags, info.OrchestratorCardTags, info.HighCardTags, err
		}
	}

	// container not found in updates
	return []string{}, []string{}, []string{}, errors.NewNotFound(entity)
}

func addTagsForContainer(ctx context.Context, containerID string, tags *utils.TagList) error {
	task, err := fetchContainerTaskWithTagsV3(ctx, containerID)
	if err != nil {
		return fmt.Errorf("Unable to get resource tags for container %s: %w", containerID, err)
	}

	addResourceTags(tags, task.ContainerInstanceTags)
	addResourceTags(tags, task.TaskTags)

	return nil
}

func fetchContainerTaskWithTagsV3(ctx context.Context, containerID string) (*v3.Task, error) {
	metaV3, err := ecsmeta.V3(ctx, containerID)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize client for metadata v3 API: %s", err)
	}
	task, err := metaV3.GetTaskWithTags(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get task with tags from metadata v3 API: %s", err)
	}
	return task, nil
}

func ecsFactory() Collector {
	return &ECSCollector{}
}

func init() {
	registerCollector(ecsCollectorName, ecsFactory, NodeRuntime)
}
